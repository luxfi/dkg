// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cscp

import (
	"errors"
	"io"
	"sync"

	"github.com/luxfi/dkg/mpc"
)

// session.go — the malicious-secure MPC session the CarryCompare circuit runs
// over. It is a thin, leak-accounted wrapper around the mpc/ substrate: every
// multiplication is a COMMITTED BGW multiplication (closer a), every open is a
// commit-then-open with binding identification (closer c), and every contributed
// random bit is committed and batch-validated (closer b). The session records
// EVERY opened value by a sanctioned tag so a test can prove the only values that
// ever leave the shared domain are {validity bit, uniform mask-open, bit-validity
// indicator, final w1} — never w, w0, or A0.

// Sentinel errors signalling a detected deviation; the driver converts the
// captured fault into a blame complaint.
var (
	errReshare = errors.New("cscp: malformed committed re-share (closer a)")
	errOpen    = errors.New("cscp: open equivocation or non-codeword (closer c)")
	errBit     = errors.New("cscp: non-{0,1} contributed bit (closer b)")
)

// Sanctioned open tags — the ONLY purposes for which a value leaves the shared
// domain. Anything else increments Recorder.OtherCt (which must stay 0).
const (
	tagValid       = "valid"       // random-bitwise validity bit r<q (∈{0,1})
	tagMaskC       = "maskC"       // per-coefficient mask-open c=(w−r) mod q (uniform)
	tagBitValidity = "bitvalidity" // batched b·(b−1)=0 indicator (0 for honest input)
	tagW1          = "w1"          // the per-coefficient HighBits output (intended public)
)

// Recorder captures every opened value, tagged by purpose, so a test asserts
// exactly the leak-free set is revealed and OtherCt stays 0. Thread-safe: the
// per-coefficient workers share one recorder.
type Recorder struct {
	mu      sync.Mutex
	Valid   []mpc.Elem
	MaskC   []mpc.Elem
	BitVal  []mpc.Elem
	W1      []mpc.Elem
	OtherCt int
}

func (r *Recorder) record(tag string, v mpc.Elem) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch tag {
	case tagValid:
		r.Valid = append(r.Valid, v)
	case tagMaskC:
		r.MaskC = append(r.MaskC, v)
	case tagBitValidity:
		r.BitVal = append(r.BitVal, v)
	case tagW1:
		r.W1 = append(r.W1, v)
	default:
		r.OtherCt++
	}
}

// tamper hooks (unexported; set only by in-package deviation tests) inject one
// malicious deviation so the closers can be exercised end-to-end in the circuit.
type tamper struct {
	reshare func(dealer int, d *mpc.ReshareDeal) *mpc.ReshareDeal
	open    func(party int, r *mpc.OpeningReveal) *mpc.OpeningReveal
	bit     func(party int, b *mpc.CommittedBit) *mpc.CommittedBit
}

// session is one coefficient's MPC context. It holds NO joint value — every
// field is either a public parameter or a degree-(threshold-1) sharing.
type session struct {
	f          *mpc.Field
	evalPoints []mpc.Elem
	threshold  int
	n          int
	gamma2     uint32
	rng        io.Reader
	rec        *Recorder
	tam        *tamper

	bitBatch []*mpc.CommittedBit // contributed bits awaiting batched validity check

	// captured deviation (first one wins; the driver mints the complaint).
	reshareFault *mpc.ReshareFault
	openFaults   []*mpc.OpeningFault
	bitFault     *mpc.BitFault
}

// ── linear (free, local, no interaction) ─────────────────────────────────────

func (s *session) constShare(v mpc.Elem) []mpc.Elem {
	out := make([]mpc.Elem, s.n)
	r := s.f.Reduce(v)
	for i := range out {
		out[i] = r
	}
	return out
}

func (s *session) add(a, b []mpc.Elem) []mpc.Elem { out, _ := s.f.AddShares(a, b); return out }
func (s *session) sub(a, b []mpc.Elem) []mpc.Elem { out, _ := s.f.SubShares(a, b); return out }
func (s *session) scalarMul(k mpc.Elem, a []mpc.Elem) []mpc.Elem {
	return s.f.ScalarMulShares(k, a)
}

// ── interactive: committed multiplication (closer a) ─────────────────────────

// mul is one malicious-secure BGW multiplication: each party deals a COMMITTED
// degree-(threshold-1) re-share of its local product; every re-share is
// degree-checked before recombination. A malformed re-share is captured as a
// ReshareFault and aborts the coefficient (errReshare).
func (s *session) mul(a, b []mpc.Elem) ([]mpc.Elem, error) {
	deals := make([]*mpc.ReshareDeal, s.n)
	for i := 0; i < s.n; i++ {
		d, err := s.f.DealReshare(s.f.Mul(a[i], b[i]), s.evalPoints, s.threshold, s.rng)
		if err != nil {
			return nil, err
		}
		if s.tam != nil && s.tam.reshare != nil {
			d = s.tam.reshare(i, d)
		}
		deals[i] = d
	}
	z, fault, err := s.f.CombineCommittedReshares(deals, s.evalPoints, s.threshold)
	if err != nil {
		return nil, err
	}
	if fault != nil {
		s.reshareFault = fault
		return nil, errReshare
	}
	return z, nil
}

// ── interactive: identifiable open (closer c) ────────────────────────────────

// open reconstructs one sharing at X=0 via commit-then-open binding and records
// the value under tag. An equivocator (revealed share ≠ committed digest) is
// captured as an OpeningFault and aborts (errOpen). A non-codeword with no
// equivocation also aborts (the corruption is an upstream re-share fault).
func (s *session) open(tag string, share []mpc.Elem) (mpc.Elem, error) {
	reveals := make([]*mpc.OpeningReveal, s.n)
	for i := 0; i < s.n; i++ {
		r, err := mpc.DealOpening(share[i], s.rng)
		if err != nil {
			return 0, err
		}
		r.Party = i
		if s.tam != nil && s.tam.open != nil {
			r = s.tam.open(i, r)
		}
		reveals[i] = r
	}
	v, faults, clean, err := s.f.IdentifiableOpen(reveals, s.evalPoints, s.threshold)
	if err != nil {
		return 0, err
	}
	if !clean {
		s.openFaults = faults
		return 0, errOpen
	}
	s.rec.record(tag, v)
	return v, nil
}

// ── interactive: committed + bit-validated random bit (closer b) ─────────────

// randomSharedBit draws one shared uniform bit b = b_0 ⊕ … ⊕ b_{N-1} from one
// COMMITTED private bit per party, XOR-folded via committed multiplications. The
// committed bits accumulate in bitBatch; checkBits validates the whole batch with
// one opened value before the bits are trusted downstream.
func (s *session) randomSharedBit() ([]mpc.Elem, error) {
	parts := make([]*mpc.CommittedBit, s.n)
	for h := 0; h < s.n; h++ {
		coin, err := mpc.RandBit(s.rng)
		if err != nil {
			return nil, err
		}
		cb, err := s.f.DealBit(coin, s.evalPoints, s.threshold, s.rng)
		if err != nil {
			return nil, err
		}
		if s.tam != nil && s.tam.bit != nil {
			cb = s.tam.bit(h, cb)
		}
		parts[h] = cb
		s.bitBatch = append(s.bitBatch, cb)
	}
	acc := append([]mpc.Elem(nil), parts[0].Shares...)
	for h := 1; h < s.n; h++ {
		prod, err := s.mul(acc, parts[h].Shares)
		if err != nil {
			return nil, err
		}
		sum := s.add(acc, parts[h].Shares)
		acc = s.sub(sum, s.scalarMul(2, prod)) // u ⊕ v = u + v − 2uv
	}
	return acc, nil
}

// checkBits runs the batched b·(b−1)=0 proof over every contributed bit since the
// last check, opening ONE Fiat-Shamir random linear combination (recorded as a
// leak-free bit-validity indicator). A non-bit is captured as a BitFault and
// aborts (errBit). It reuses the standalone mpc.BatchedBitCheck for the proof and
// additionally records the combination open so the leak accounting is complete.
func (s *session) checkBits() error {
	if len(s.bitBatch) == 0 {
		return nil
	}
	ok, fault, err := s.f.BatchedBitCheck(s.bitBatch, s.evalPoints, s.threshold, s.rng)
	if err != nil {
		return err
	}
	// Record the indicator (0 when honest) so every reveal in the run is tagged.
	if ok {
		s.rec.record(tagBitValidity, 0)
	} else {
		s.rec.record(tagBitValidity, 1)
		s.bitFault = fault
		return errBit
	}
	s.bitBatch = s.bitBatch[:0]
	return nil
}
