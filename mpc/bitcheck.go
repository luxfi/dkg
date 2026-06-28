// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"io"

	"github.com/luxfi/dkg/transcript"
)

// bitcheck.go — closer (b): batched bit-validity proof.
//
// SharedRandomBit and the CSCP mask sampler trust each party's private input to
// be a genuine bit b ∈ {0,1}. A malicious party can feed a non-bit, skewing the
// mask. We close this with ONE opened value over the whole batch:
//
//   for each party's committed bit-sharing ⟨b_m⟩, form ⟨b_m·(b_m-1)⟩ via a
//   committed BGW multiplication (so the squaring's re-shares are degree-checked
//   too); take a random PUBLIC linear combination Σ_m ρ_m·⟨b_m(b_m-1)⟩ whose
//   coefficients ρ_m are derived by Fiat-Shamir from the bit COMMITMENTS (the
//   adversary fixes its bits before the challenge); open it ONCE and assert 0.
//
// SOUNDNESS. b·(b-1) = 0 iff b ∈ {0,1}. If any committed bit is a non-bit then
// some v_m = b_m(b_m-1) ≠ 0, and Σ_m ρ_m v_m is a nonzero linear form in ρ, so
// it equals 0 with probability exactly 1/q over uniform ρ — the batch open
// catches a non-bit except with probability 1/q. Binding the bits before drawing
// ρ (commitment + collision resistance) prevents the adversary from crafting v_m
// to cancel. On failure we drill down — opening each ⟨b_m(b_m-1)⟩ of the DEAD
// (about-to-be-retried) computation — to name the offending party (BitFault),
// whose committed bit b_m the blame re-check reconstructs and confirms is a
// non-bit. Opening a dead bit leaks nothing: the masked computation is discarded
// and re-run with fresh randomness.

// CommittedBit is a party's committed private input bit: the bit shared at
// degree threshold-1, the nonce, and the binding commitment.
type CommittedBit struct {
	Shares []Elem
	Nonce  []byte
	Commit []byte
}

// BitFault carries publicly-re-checkable evidence that a party contributed a
// non-{0,1} bit: its committed N-share bit-sharing, whose reconstructed secret b
// satisfies b·(b-1) != 0 mod q. The blame bridge mints a ReasonBadBit complaint.
type BitFault struct {
	Party  int
	Shares []Elem
	Nonce  []byte
	Commit []byte
	Sig    []byte
}

// CommitBit commits a party to its bit-sharing (cSHAKE domain disjoint from
// re-share and opening commitments).
func CommitBit(shares []Elem, nonce []byte) []byte {
	return commitBytes(csBitCommit, shares, nonce)
}

// DealBit shares a private bit b ∈ {0,1} at degree threshold-1 with a binding
// commitment. b is the party's own coin and is never opened unless the batch
// check fails.
func (f *Field) DealBit(b bool, evalPoints []Elem, threshold int, rng io.Reader) (*CommittedBit, error) {
	var bit Elem
	if b {
		bit = 1
	}
	shares, err := f.ShareScalar(bit, evalPoints, threshold, rng)
	if err != nil {
		return nil, err
	}
	nonce, err := NewNonce(rng)
	if err != nil {
		return nil, err
	}
	return &CommittedBit{Shares: shares, Nonce: nonce, Commit: CommitBit(shares, nonce)}, nil
}

// bitChallenge derives the Fiat-Shamir linear-combination coefficients ρ_m ∈
// GF(q), one per committed bit, by hashing all bit commitments into a cSHAKE256
// stream and rejection-sampling each ρ_m below q. The bits are bound by their
// commitments before ρ is known, so the adversary cannot tune v_m to cancel.
func (f *Field) bitChallenge(bits []*CommittedBit) ([]Elem, error) {
	t := transcript.NewWithDomain(cShakeFn, "bitcheck-challenge-v1")
	for _, b := range bits {
		t.Append("commit", b.Commit)
	}
	seed := t.Hash()
	rd := NewCShakeReader(cShakeFn, "bitcheck-rho-v1", seed[:])
	rho := make([]Elem, len(bits))
	for m := range rho {
		v, err := f.Rand(rd)
		if err != nil {
			return nil, err
		}
		rho[m] = v
	}
	return rho, nil
}

// BatchedBitCheck proves every committed input bit is in {0,1} with ONE opened
// value. It first degree-checks each committed bit-sharing (a malformed one is a
// BitFault directly); then forms ⟨b_m(b_m-1)⟩ via a committed BGW multiplication,
// random-linear-combines the products under the Fiat-Shamir ρ, opens once, and
// asserts 0. ok is true iff all bits are valid; otherwise fault names the first
// offending party. Requires N >= 2T-1. A ReshareFault surfacing from the
// committed squaring is reported as a BitFault on that party (its squaring
// re-share was malformed — equally a deviation to blame).
func (f *Field) BatchedBitCheck(bits []*CommittedBit, evalPoints []Elem, threshold int, rng io.Reader) (ok bool, fault *BitFault, err error) {
	n := len(evalPoints)
	if len(bits) == 0 {
		return false, nil, ErrShape
	}
	if n < 2*threshold-1 {
		return false, nil, ErrNotEnoughParties
	}
	// 1. degree-check + commitment-bind each contributed bit-sharing.
	for m, b := range bits {
		if b == nil || len(b.Shares) != n {
			return false, nil, ErrShape
		}
		if !equalConst(b.Commit, CommitBit(b.Shares, b.Nonce)) || !f.CheckDegree(evalPoints, b.Shares, threshold) {
			return false, &BitFault{Party: m, Shares: b.Shares, Nonce: b.Nonce, Commit: b.Commit}, nil
		}
	}
	// 2. ⟨b_m(b_m-1)⟩ = ⟨b_m²⟩ - ⟨b_m⟩ via one committed multiplication each.
	prods := make([][]Elem, len(bits))
	for m, b := range bits {
		sq, rf, e := f.MulSharesCommitted(b.Shares, b.Shares, evalPoints, threshold, rng)
		if e != nil {
			return false, nil, e
		}
		if rf != nil {
			return false, &BitFault{Party: m, Shares: b.Shares, Nonce: b.Nonce, Commit: b.Commit}, nil
		}
		diff, e := f.SubShares(sq, b.Shares) // b² - b
		if e != nil {
			return false, nil, e
		}
		prods[m] = diff
	}
	// 3. Fiat-Shamir random linear combination, opened once.
	rho, e := f.bitChallenge(bits)
	if e != nil {
		return false, nil, e
	}
	combo := make([]Elem, n)
	for m := range bits {
		scaled := f.ScalarMulShares(rho[m], prods[m])
		combo, _ = f.AddShares(combo, scaled)
	}
	val, e := f.Reconstruct(evalPoints[:threshold], combo[:threshold])
	if e != nil {
		return false, nil, e
	}
	if val == 0 {
		return true, nil, nil
	}
	// 4. drill down: open each product on the DEAD computation to name the party.
	for m := range bits {
		v, e := f.Reconstruct(evalPoints[:threshold], prods[m][:threshold])
		if e != nil {
			return false, nil, e
		}
		if v != 0 {
			b := bits[m]
			return false, &BitFault{Party: m, Shares: b.Shares, Nonce: b.Nonce, Commit: b.Commit}, nil
		}
	}
	// The combination was nonzero but no single product is — only possible if a
	// committed product re-share was tampered; report shape error (never silently
	// accept a nonzero batch).
	return false, nil, ErrShape
}
