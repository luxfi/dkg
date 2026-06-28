// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import (
	"fmt"

	"github.com/luxfi/dkg/ring"
)

// reconstruct.go — quorum reconstruction of the full short secret (s1, s2) from
// any T qualifying parties' replicated shares, via the balanced partition of
// partition.go. Every one of the C(N,N−T+1) subset secrets is summed EXACTLY
// once (the partition assigns each subset to a single active signer), so the
// result is the true (s1, s2) = (Σ_S s1^(S), Σ_S s2^(S)).
//
// This is the verification oracle that PROVES the dealerless key is genuine: the
// reconstructed (s1, s2) are short (‖·‖∞ ≤ C(N,M)·η — the wall-beating bound)
// and reproduce the published group key (A·s1+s2 = T, Power2Round = t1). It is
// also the basis of a quorum-reconstruct signer. The DEALERLESS, NO-RECONSTRUCT
// keygen never calls this — it derives the public key from the public per-subset
// commitments (Generate). Reconstruction is a separate, threshold-gated act:
// it requires T cooperating parties and is used only to sign or to audit.

// Reconstruct sums each subset secret exactly once across the active signers'
// holdings (balanced partition), returning the full short secret (s1 ∈ R_q^L,
// s2 ∈ R_q^K) in standard coefficient form. active must be a sorted,
// duplicate-free set of exactly T party ids; each party must hold every subset
// it was assigned (which it does by construction).
func Reconstruct(keys *Keys, active []int) (s1, s2 ring.Vector, err error) {
	if keys == nil || keys.Group == nil {
		return nil, nil, fmt.Errorf("rss: nil keys")
	}
	prof := keys.Group.Profile
	r := prof.Ring
	part, err := RSSRecover(active, keys.T, keys.N)
	if err != nil {
		return nil, nil, err
	}
	s1 = ring.NewVec(r, prof.L)
	s2 = ring.NewVec(r, prof.K)
	for j, masks := range part {
		party := keys.Parties[active[j]]
		for _, mask := range masks {
			ss, ok := party.Held[mask]
			if !ok {
				return nil, nil, fmt.Errorf("rss: signer %d missing assigned subset 0b%b", active[j], mask)
			}
			ring.VecAdd(r, s1, ss.S1, s1)
			ring.VecAdd(r, s2, ss.S2, s2)
		}
	}
	return s1, s2, nil
}

// InfNorm returns the centered ∞-norm of a vector: max over all coefficients of
// |center(c)|, where center maps [0,q) to (−q/2, q/2]. The short-secret bound is
// the load-bearing wall-beating measurement.
func InfNorm(r *ring.Ring, v ring.Vector) uint64 {
	q := r.Q()
	half := q / 2
	var max uint64
	for _, p := range v {
		for _, c := range p.Coeffs[0] {
			d := c
			if c > half {
				d = q - c // |negative representative|
			}
			if d > max {
				max = d
			}
		}
	}
	return max
}

// RecomputeT computes T = A·s1 + s2 in standard coefficient form from an
// explicit (s1, s2) — the reconstructed-secret view of the public key, used to
// cross-check that the no-reconstruct group key (built from public per-subset
// commitments) equals the reconstructed-secret key. Same proven NTT-Mont path as
// subsetCommit.
func RecomputeT(prof *ring.Profile, s1, s2 ring.Vector) ring.Vector {
	r := prof.Ring
	s1ntt := ring.CopyVec(s1)
	ring.NTTVec(r, s1ntt)
	as := ring.NewVec(r, prof.K)
	ring.MatVecMul(r, prof.A, s1ntt, as)
	ring.ConvertVecFromNTT(r, as)
	t := ring.NewVec(r, prof.K)
	ring.VecAdd(r, as, s2, t)
	return t
}

// MaxSecretNorm returns the worst-case ‖s‖∞ bound C(N,M)·η for the committee:
// the largest the reconstructed short secret can be. This is small (≤ 20·η for
// N≤6), versus ‖B·u‖∞ ≈ q/2 for the large-blinding vss key — the quantitative
// statement of why the RSS key is stock-FIPS-204-signable and the vss key is not.
func MaxSecretNorm(t, n int, eta uint64) uint64 {
	return uint64(NumSubsets(t, n)) * eta
}
