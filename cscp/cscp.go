// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cscp is the malicious-secure CarryCompare secure-comparison (TALUS
// Phase B) of luxfi/dkg. It realises FIPS-204 HighBits over a degree-(T-1)
// Shamir sharing of a commitment w — recovering w1 = HighBits(w) WITHOUT any
// node forming w, its low part w0, or the aggregate low sum A0 — and closes the
// three deviations a malicious party could mount against the semi-honest
// circuit:
//
//	(a) inconsistent re-share  → committed re-shares (mpc.MulSharesCommitted,
//	    mpc.CheckDegree): every multiplication and the additive→Shamir step
//	    carry a cSHAKE256 commitment and are degree-checked before use.
//	(b) non-{0,1} random bit   → batched bit validity (mpc.BatchedBitCheck):
//	    each contributed private bit is committed and proven b·(b−1)=0 by ONE
//	    opened Fiat-Shamir combination.
//	(c) equivocated mask-open  → identifiable open (mpc.IdentifiableOpen): a
//	    commit-then-open round names any party whose revealed share does not
//	    open its committed digest.
//
// CORRECTNESS ORACLE. The boundary-count identity the circuit computes,
// w1 = (Σ_{k=1..16}[w > (2k−1)γ2]) mod 16, is coefficient-exact against
// ring.HighBitsVec / ring.Decompose on EVERY residue for the ML-DSA-65/87
// parameter set (γ2 = 261888, m = (q−1)/2γ2 = 16 power-of-two buckets); that is
// the in-the-clear test oracle. ML-DSA-44 (γ2 = 95232, m = 44) is out of scope.
//
// LEAK-FREENESS. Every opened value is recorded by a sanctioned tag; the only
// values that ever leave the shared domain are the random-bitwise validity bit
// (∈{0,1}), the per-coefficient mask-open c = (w−r) mod q (uniform), the batched
// bit-validity indicator (0 when honest), and the final w1 — never w, w0, or A0.
// A test asserts Recorder.OtherCt == 0.
package cscp

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/luxfi/dkg/mpc"
	"github.com/luxfi/dkg/ring"
)

// MLDSAGamma2 is the FIPS-204 low-order rounding range γ2 for ML-DSA-65/87,
// (q−1)/32. It is the only γ2 the boundary-count fold (m = 16 power-of-two
// buckets) is proven for.
const MLDSAGamma2 uint32 = 261888

// buckets is m = (q−1)/(2γ2) = 16 for ML-DSA-65/87: the number of HighBits
// buckets, a power of two so the mod-m fold is a single AND of the indicators.
const buckets = 16

// mldsaQ is the ML-DSA prime q = 2^23 − 2^13 + 1; the CSCP scope.
const mldsaQ = 8380417

// Errors.
var (
	ErrParamSet  = errors.New("dkg/cscp: proven for ML-DSA-65/87 (γ2=261888, m=16) only")
	ErrShape     = errors.New("dkg/cscp: commitment-share / eval-point shape mismatch")
	ErrRandBits  = errors.New("dkg/cscp: random-bitwise generation exhausted retries")
	ErrDeviation = errors.New("dkg/cscp: a malicious deviation was detected (see Result)")
)

// Result reports a detected deviation so the caller mints the matching blame
// complaint (mpc.NewReshareComplaint / NewOpeningComplaint / NewBitComplaint).
// On an honest run all fault fields are nil and Recorder holds the leak-free
// transcript.
type Result struct {
	Recorder      *Recorder
	ReshareFault  *mpc.ReshareFault
	OpeningFaults []*mpc.OpeningFault
	BitFault      *mpc.BitFault
}

// newSession builds one coefficient's malicious-secure session over field f.
func newSession(f *mpc.Field, evalPoints []mpc.Elem, threshold int, gamma2 uint32, rng io.Reader, rec *Recorder, tam *tamper) (*session, error) {
	n := len(evalPoints)
	if threshold < 1 || n < threshold {
		return nil, mpc.ErrInvalidThreshold
	}
	if n < 2*threshold-1 {
		return nil, mpc.ErrNotEnoughParties
	}
	if gamma2 != MLDSAGamma2 || f.Q() != mldsaQ {
		return nil, ErrParamSet
	}
	return &session{
		f: f, evalPoints: evalPoints, threshold: threshold, n: n,
		gamma2: gamma2, rng: rng, rec: rec, tam: tam,
	}, nil
}

// resultFrom collects a session's first captured deviation into a Result.
func resultFrom(s *session, rec *Recorder) *Result {
	return &Result{Recorder: rec, ReshareFault: s.reshareFault, OpeningFaults: s.openFaults, BitFault: s.bitFault}
}

// SecureHighBitsVec is the public driver: it computes w1 = HighBits(Σ_i g_i mod q)
// coefficient-wise from the per-party ADDITIVE commitment shares commitShares
// (commitShares[i] is party i's g_i, a length-K poly-vector; Σ_i g_i ≡ w), via
// the malicious-secure circuit, with NO node ever forming w, w0, or A0. evalPoints
// is parallel to commitShares (N = len ≥ 2T−1 for honest majority). The 256·K
// coefficients are independent and run in parallel; each draws a cSHAKE256 stream
// from one master seed read from rng, so the result is reproducible and the
// workers are race-free. rec (optional) records every opened value for the
// leak-free proof.
//
// On an honest run it returns the w1 vector and a Result with nil faults. If a
// malicious deviation is detected it returns ErrDeviation and a Result naming the
// fault (the caller files the blame complaint and retries with a fresh nonce).
func SecureHighBitsVec(profile *ring.Profile, gamma2 uint32, commitShares []ring.Vector, evalPoints []mpc.Elem, threshold int, rng io.Reader, rec *Recorder) (ring.Vector, *Result, error) {
	if profile == nil || profile.Ring == nil {
		return nil, nil, ErrShape
	}
	f, err := mpc.FieldFromProfile(profile)
	if err != nil {
		return nil, nil, err
	}
	if gamma2 != MLDSAGamma2 || f.Q() != mldsaQ {
		return nil, nil, ErrParamSet
	}
	n := len(commitShares)
	if n == 0 || len(evalPoints) != n {
		return nil, nil, ErrShape
	}
	if threshold < 1 || n < 2*threshold-1 {
		return nil, nil, mpc.ErrNotEnoughParties
	}
	K := profile.K
	N := profile.Ring.N()
	for _, sh := range commitShares {
		if len(sh) != K {
			return nil, nil, ErrShape
		}
	}

	var master [32]byte
	if _, err := io.ReadFull(rng, master[:]); err != nil {
		return nil, nil, err
	}

	out := ring.NewVec(profile.Ring, K)
	type coeff struct{ k, j int }
	total := K * N
	jobs := make(chan coeff, total)
	for k := range K {
		for j := range N {
			jobs <- coeff{k, j}
		}
	}
	close(jobs)

	workers := min(runtime.NumCPU(), total)
	var (
		mu       sync.Mutex
		firstErr error
		firstRes *Result
		wg       sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			parts := make([]mpc.Elem, n)
			for c := range jobs {
				mu.Lock()
				stop := firstErr != nil
				mu.Unlock()
				if stop {
					return
				}
				for i := range n {
					parts[i] = commitShares[i][c.k].Coeffs[0][c.j] % mldsaQ
				}
				var tag [8]byte
				binary.BigEndian.PutUint32(tag[0:4], uint32(c.k))
				binary.BigEndian.PutUint32(tag[4:8], uint32(c.j))
				rd := mpc.NewCShakeReader("LUX-DKG-CSCP", "coeff-stream-v1", append(append([]byte{}, master[:]...), tag[:]...))
				s, err := newSession(f, evalPoints, threshold, gamma2, rd, rec, nil)
				if err != nil {
					recordErr(&mu, &firstErr, &firstRes, err, nil)
					return
				}
				v, err := s.secureHighBitsCoeff(parts)
				if err != nil {
					recordErr(&mu, &firstErr, &firstRes, err, resultFrom(s, rec))
					return
				}
				out[c.k].Coeffs[0][c.j] = uint64(v)
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		if isDeviation(firstErr) {
			return nil, firstRes, ErrDeviation
		}
		return nil, firstRes, firstErr
	}
	return out, &Result{Recorder: rec}, nil
}

// recordErr stores the first worker error + result under the mutex.
func recordErr(mu *sync.Mutex, firstErr *error, firstRes **Result, err error, res *Result) {
	mu.Lock()
	defer mu.Unlock()
	if *firstErr == nil {
		*firstErr = err
		*firstRes = res
	}
}

// isDeviation reports whether err is one of the three malicious-deviation
// sentinels (vs an environment/IO error).
func isDeviation(err error) bool {
	return errors.Is(err, errReshare) || errors.Is(err, errOpen) || errors.Is(err, errBit)
}
