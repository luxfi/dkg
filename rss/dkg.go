// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import (
	"fmt"

	"github.com/luxfi/dkg/ring"
	"golang.org/x/crypto/sha3"
)

// dkg.go — the dealerless Replicated-Secret-Sharing key generation. No trusted
// dealer ever holds the full (s1, s2): each M-subset's short secret is sampled
// by that subset's LEADER (its lowest-indexed member) from the leader's own
// contributed entropy, and is replicated to the subset's other members over the
// authenticated channel. Because no single party is a member of every subset
// (whenever T ≥ 2), no single party ever learns the whole key. The group public
// key is derived from the PUBLIC per-subset commitments t^(S) = A·s1^(S)+s2^(S)
// summed in the open — never from reconstructing a secret (no-reconstruct).
//
// Security of the per-subset-leader design (vs. a single global dealer): a
// corrupt coalition B with |B| ≤ T−1 is disjoint from at least one whole
// M-subset S* (because |complement(B)| ≥ N−(T−1) = M). Every member of S*,
// including its leader, is therefore honest, so s^(S*) is freshly random and
// unknown to B; it information-theoretically masks the key. A malicious leader
// can only bias subsets it belongs to — never the masking subset S* — and the
// share-validity gate (η-bound) keeps every contribution short, so the key
// stays a genuine small-secret FIPS-204 key. This is the dealerless guarantee:
// the key is unbiased and hidden given ≥1 honest party in the masking subset.

// SubsetSecret is one M-subset's short secret (s1^(S) ∈ R_q^L, s2^(S) ∈ R_q^K),
// both with coefficients in [−η, η]. It is replicated to every member of the
// subset and to no one else.
type SubsetSecret struct {
	Mask uint64      // subset bitmask (bit i ⇔ party i ∈ subset)
	S1   ring.Vector // length L, χ_η
	S2   ring.Vector // length K, χ_η
}

// PartyShare is one party's complete private holding: every subset secret whose
// subset contains the party. The party never holds any other subset's secret,
// so it never holds the full (s1, s2).
type PartyShare struct {
	ID   int
	Held map[uint64]*SubsetSecret
}

// GroupKey is the no-reconstruct public output of the DKG. T = A·s1 + s2 is the
// FIPS-204-shaped public inner vector (standard coefficient form); T1 = high
// bits (the published t1, pk = (rho, t1)); T0 = low bits (needed by signers at
// hint time). Rho is the jointly-contributed public seed for A = ExpandA(rho)
// (binding A to rho is the FIPS-204 consumer's concern via Profile.WithMatrices;
// see Generate).
type GroupKey struct {
	Profile *ring.Profile
	Rho     []byte
	T       ring.Vector
	T1      ring.Vector
	T0      ring.Vector
}

// Keys is the full DKG result: the shared public key plus one private holding
// per party.
type Keys struct {
	T, N    int
	Group   *GroupKey
	Parties []*PartyShare
}

// LeaderOf returns the leader of a subset: its lowest-indexed member. The leader
// samples that subset's short secret and replicates it to the other members.
func LeaderOf(mask uint64) int {
	for i := 0; mask != 0; i++ {
		if mask&(uint64(1)<<uint(i)) != 0 {
			return i
		}
	}
	return -1
}

// rhoFromSeeds derives the joint public seed rho = SHAKE256("rss-rho-v1" ‖ seed_0
// ‖ … ‖ seed_{N−1})[:32]. Every party contributes; rho is unbiased given ≥1
// honest contributor (with the commit-then-reveal wrapper of the protocol layer
// preventing a rushing party from biasing the last contribution). 32 bytes, the
// FIPS-204 ρ length.
func rhoFromSeeds(partySeeds [][]byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("rss-rho-v1"))
	for _, s := range partySeeds {
		_, _ = h.Write(s)
	}
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// deriveSubsetSecret samples a subset's short secret (s1^(S), s2^(S)) ← χ_η^L ×
// χ_η^K from the LEADER's contributed entropy, domain-separated by the subset
// mask. Deterministic in (leaderSeed, mask): the leader can recompute and
// replicate it; no other party can derive it without leaderSeed.
func deriveSubsetSecret(prof *ring.Profile, leaderSeed []byte, mask uint64) (*SubsetSecret, error) {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("rss-subset-v1"))
	_, _ = h.Write(leaderSeed)
	var mb [8]byte
	for i := 0; i < 8; i++ {
		mb[i] = byte(mask >> (8 * uint(i)))
	}
	_, _ = h.Write(mb[:])
	seed := make([]byte, 32)
	_, _ = h.Read(seed)

	prng, err := ring.NewKeyedPRNG(seed)
	if err != nil {
		return nil, fmt.Errorf("rss: subset prng: %w", err)
	}
	eta := prof.Eta
	if eta == 0 {
		return nil, fmt.Errorf("rss: profile %q has no χ_η bound (not an ML-DSA profile)", prof.Name)
	}
	s1 := ring.SampleBoundedUniformVec(prof.Ring, prof.L, eta, prng)
	s2 := ring.SampleBoundedUniformVec(prof.Ring, prof.K, eta, prng)
	return &SubsetSecret{Mask: mask, S1: s1, S2: s2}, nil
}

// subsetCommit computes the PUBLIC per-subset commitment t^(S) = A·s1^(S) +
// s2^(S) in standard coefficient form. Aggregating these over all subsets yields
// the group key with no secret ever reconstructed. Uses the proven NTT-Mont
// path: A (NTT-Mont) · NTT(s1) → plain-NTT A·s1, INTT-only back to coeff, then
// add the coeff-form s2.
func subsetCommit(prof *ring.Profile, ss *SubsetSecret) ring.Vector {
	r := prof.Ring
	s1ntt := ring.CopyVec(ss.S1)
	ring.NTTVec(r, s1ntt)
	as := ring.NewVec(r, prof.K)
	ring.MatVecMul(r, prof.A, s1ntt, as) // plain-NTT A·s1^(S)
	ring.ConvertVecFromNTT(r, as)        // → coeff form, true A·s1^(S)
	t := ring.NewVec(r, prof.K)
	ring.VecAdd(r, as, ss.S2, t) // A·s1^(S) + s2^(S)
	return t
}

// Generate runs the dealerless RSS DKG for an (T, N) committee over the given
// ML-DSA profile, driven by one contributed 32-byte seed per party. It is
// deterministic in (prof, t, n, partySeeds) so honest parties recompute an
// identical transcript and a chain can pin a KAT.
//
// The caller binds A to the public key: for byte-stock-FIPS-204 output, derive
// rho jointly first (rhoFromSeeds), set A = ExpandA(rho) via prof.WithMatrices,
// then call Generate; the returned GroupKey.Rho will equal that rho. With the
// default profile matrix (DeriveUniformMatrix tag) the DKG is still correct and
// self-consistent — the key is genuine for THAT A — it simply is not bound to a
// FIPS-204 ExpandA(rho).
//
// Fail-closed on any committee that fails the per-(N,T) norm bound
// (ValidateCommittee): 2 ≤ T ≤ N ≤ MaxBitmaskParties and τ·C(N,N−T+1)·η < γ2.
func Generate(prof *ring.Profile, t, n int, partySeeds [][]byte) (*Keys, error) {
	if err := ValidateCommittee(t, n); err != nil {
		return nil, err
	}
	if prof == nil {
		return nil, fmt.Errorf("rss: nil profile")
	}
	if len(partySeeds) != n {
		return nil, fmt.Errorf("rss: got %d party seeds, want N=%d", len(partySeeds), n)
	}
	for i, s := range partySeeds {
		if len(s) < 32 {
			return nil, fmt.Errorf("rss: party %d seed is %d bytes, want ≥32", i, len(s))
		}
	}
	r := prof.Ring

	rho := rhoFromSeeds(partySeeds)

	parties := make([]*PartyShare, n)
	for i := range parties {
		parties[i] = &PartyShare{ID: i, Held: map[uint64]*SubsetSecret{}}
	}

	// T accumulator (standard coefficient form). Built from PUBLIC per-subset
	// commitments only — no secret is summed across subsets at any one party.
	T := ring.NewVec(r, prof.K)

	for _, mask := range EnumerateSubsets(t, n) {
		leader := LeaderOf(mask)
		ss, err := deriveSubsetSecret(prof, partySeeds[leader], mask)
		if err != nil {
			return nil, err
		}
		// Replicate to every member of the subset (the leader included).
		for _, member := range SubsetMembers(mask, n) {
			parties[member].Held[mask] = ss
		}
		// Aggregate the public commitment.
		ring.VecAdd(r, T, subsetCommit(prof, ss), T)
	}

	t1, t0 := ring.Power2RoundVec(r, T)
	return &Keys{
		T: t, N: n,
		Group: &GroupKey{
			Profile: prof,
			Rho:     rho,
			T:       T,
			T1:      t1,
			T0:      t0,
		},
		Parties: parties,
	}, nil
}
