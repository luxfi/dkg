// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"github.com/luxfi/dkg/ring"
)

// party.go — the Pedersen-VSS arithmetic core, generic over a *ring.Profile.
//
// All routines preserve the one domain convention (ring/ops.go): public
// matrices A, B are NTT-Montgomery; secret coefficient vectors are standard
// form; commits and the verification LHS/RHS live in plain-NTT form; the
// aggregated commit T is converted to standard coefficient form before
// KeyFinalize. Porting the exact corona/dkg2 operation sequence — not
// re-deriving it — is what makes the Ringtail instantiation byte-identical to
// the KAT-pinned corona arithmetic and well-defined at the ML-DSA parameters.

// computeCommits builds the Pedersen commit vector C_k = A·NTT(c_k) + B·NTT(r_k)
// for k = 0..t-1, returning t vectors in R_q^K (plain-NTT form). cCoeffs and
// rCoeffs are the standard-form coefficient vectors of f_i and g_i (length t,
// each R_q^L); they are NOT mutated (each is copied before the in-place NTT).
func computeCommits(p *ring.Profile, cCoeffs, rCoeffs []ring.Vector) []ring.Vector {
	r := p.Ring
	t := len(cCoeffs)
	commits := make([]ring.Vector, t)
	for k := range t {
		cNTT := ring.CopyVec(cCoeffs[k])
		rNTT := ring.CopyVec(rCoeffs[k])
		ring.NTTVec(r, cNTT)
		ring.NTTVec(r, rNTT)
		ac := ring.NewVec(r, p.K)
		br := ring.NewVec(r, p.K)
		ring.MatVecMul(r, p.A, cNTT, ac)
		ring.MatVecMul(r, p.B, rNTT, br)
		out := ring.NewVec(r, p.K)
		ring.VecAdd(r, ac, br, out)
		commits[k] = out
	}
	return commits
}

// hornerEval evaluates f(x) = Σ_k coeffs[k]·x^k over R_q^L in standard
// coefficient form via Horner's method:
//
//	f(x) = c_0 + x·(c_1 + x·(c_2 + … ))
//
// x is the evaluation point (a small positive integer = recipient index + 1).
// The scalar multiply is applied per coefficient mod q (domain-agnostic), so
// the result is the standard-form share f_i(x).
func hornerEval(r *ring.Ring, coeffs []ring.Vector, x uint64) ring.Vector {
	L := len(coeffs[0])
	t := len(coeffs)
	result := ring.NewVec(r, L)
	for k := t - 1; k >= 0; k-- {
		if k < t-1 {
			ring.ScalarMulVec(r, result, x, result)
		}
		ring.VecAdd(r, result, coeffs[k], result)
	}
	return result
}

// verifyPedersen checks the Pedersen identity for a (share, blind) pair against
// a dealer's commit vector at the recipient evaluation point:
//
//	A·NTT(share) + B·NTT(blind)  ?=  Σ_{k=0}^{t-1} point^k · C_k   (plain-NTT)
//
// Returns true iff the identity holds. The comparison is constant-time across
// all K·n coefficient slots — no early exit on the first mismatched slot, so a
// timing observer learns only the single equal/not-equal bit (component 6
// malformed-share rejection; corona RED-DKG-REVIEW Findings 5/6). share and
// blind are NOT mutated.
func verifyPedersen(p *ring.Profile, share, blind ring.Vector, commits []ring.Vector, point uint64) bool {
	r := p.Ring

	// LHS = A·NTT(share) + B·NTT(blind), plain-NTT.
	sNTT := ring.CopyVec(share)
	bNTT := ring.CopyVec(blind)
	ring.NTTVec(r, sNTT)
	ring.NTTVec(r, bNTT)
	as := ring.NewVec(r, p.K)
	bb := ring.NewVec(r, p.K)
	ring.MatVecMul(r, p.A, sNTT, as)
	ring.MatVecMul(r, p.B, bNTT, bb)
	lhs := ring.NewVec(r, p.K)
	ring.VecAdd(r, as, bb, lhs)

	// RHS = Σ_k point^k · C_k via Horner in the (plain-NTT) commit domain.
	t := len(commits)
	rhs := ring.NewVec(r, p.K)
	for k := t - 1; k >= 0; k-- {
		if k < t-1 {
			ring.ScalarMulVec(r, rhs, point, rhs)
		}
		ring.VecAdd(r, rhs, commits[k], rhs)
	}

	return ring.ConstantTimeVecEqual(lhs, rhs) == 1
}

// aggregateGroupCommit sums the dealers' constant-term commits C_{i,0} into the
// group commit T = Σ_i C_{i,0} and converts it to standard coefficient form,
// yielding the FIPS-204-shaped / Ringtail-shaped public inner vector A·s1+B·u.
// NO secret is reconstructed: T is a sum of PUBLIC commits.
func aggregateGroupCommit(p *ring.Profile, dealerCommits [][]ring.Vector) ring.Vector {
	r := p.Ring
	T := ring.NewVec(r, p.K) // plain-NTT accumulator
	for _, commits := range dealerCommits {
		ring.VecAdd(r, T, commits[0], T)
	}
	ring.ConvertVecFromNTT(r, T) // → standard coefficient form
	return T
}

// aggregateShare sums the per-dealer shares addressed to one recipient into
// that recipient's aggregated secret share s_j = Σ_i f_i(j) (standard form).
// This is the ONLY secret a party retains; the master secret s1 = Σ_i c_{i,0}
// is never formed (it would require summing the contributions, which no
// envelope carries).
func aggregateShare(p *ring.Profile, shares []ring.Vector) ring.Vector {
	r := p.Ring
	s := ring.NewVec(r, p.L)
	for _, sh := range shares {
		ring.VecAdd(r, s, sh, s)
	}
	return s
}
