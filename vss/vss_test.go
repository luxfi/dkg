// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/ring"
)

// committee builds n long-term identities + NodeIDs for a test committee.
func committee(t *testing.T, n int) ([]*channel.IdentityKey, []channel.NodeID) {
	t.Helper()
	ids := make([]*channel.IdentityKey, n)
	nodes := make([]channel.NodeID, n)
	for i := range n {
		id, err := channel.GenerateIdentity(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		nodes[i] = channel.NodeID{byte(i + 1), 0xAB}
	}
	return ids, nodes
}

// lagrangeAtZero returns the Lagrange coefficients λ_j over GF(q) at x=0 for the
// evaluation points {1,…,t} (1-indexed). TEST-ONLY: the library never does
// this; reconstruction lives here purely to VALIDATE that the dealerless DKG
// produced shares of the right secret.
func lagrangeAtZero(points []uint64, q uint64) []uint64 {
	Q := new(big.Int).SetUint64(q)
	out := make([]uint64, len(points))
	for j := range points {
		num := big.NewInt(1)
		den := big.NewInt(1)
		xj := new(big.Int).SetUint64(points[j])
		for m := range points {
			if m == j {
				continue
			}
			xm := new(big.Int).SetUint64(points[m])
			num.Mul(num, xm)
			num.Mod(num, Q)
			d := new(big.Int).Sub(xm, xj)
			d.Mod(d, Q)
			den.Mul(den, d)
			den.Mod(den, Q)
		}
		den.ModInverse(den, Q)
		num.Mul(num, den)
		num.Mod(num, Q)
		out[j] = num.Uint64()
	}
	return out
}

// reconstruct combines a subset of shares via Lagrange at 0 into the secret
// vector (standard coeff form). TEST-ONLY.
func reconstruct(r *ring.Ring, shares map[int]ring.Vector, subset []int, L int) ring.Vector {
	points := make([]uint64, len(subset))
	for i, idx := range subset {
		points[i] = uint64(idx + 1)
	}
	lambda := lagrangeAtZero(points, r.Q())
	acc := ring.NewVec(r, L)
	tmp := ring.NewVec(r, L)
	for i, idx := range subset {
		ring.ScalarMulVec(r, shares[idx], lambda[i], tmp)
		ring.VecAdd(r, acc, tmp, acc)
	}
	return acc
}

// recomputeT computes T' = A·NTT(s1) + B·NTT(u) in standard coeff form, the
// group-key root, from reconstructed s1, u. TEST-ONLY validation.
func recomputeT(p *ring.Profile, s1, u ring.Vector) ring.Vector {
	r := p.Ring
	sN := ring.CopyVec(s1)
	uN := ring.CopyVec(u)
	ring.NTTVec(r, sN)
	ring.NTTVec(r, uN)
	as := ring.NewVec(r, p.K)
	bu := ring.NewVec(r, p.K)
	ring.MatVecMul(r, p.A, sN, as)
	ring.MatVecMul(r, p.B, uN, bu)
	T := ring.NewVec(r, p.K)
	ring.VecAdd(r, as, bu, T)
	ring.ConvertVecFromNTT(r, T)
	return T
}

// runCorrect runs a DKG and validates the no-reconstruct group key equals
// A·s1 + B·u for the secret reconstructed (in-test) from the shares.
func runCorrect(t *testing.T, profile *ring.Profile, n, tt int) *Result {
	t.Helper()
	ids, nodes := committee(t, n)
	res, err := RunDKG(profile, n, tt, ids, nodes, [32]byte{0xC0, 0xFE}, rand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if res.GroupKey == nil || len(res.GroupKey.Finalized) != profile.K {
		t.Fatalf("group key shape wrong")
	}
	if len(res.Shares) != n {
		t.Fatalf("expected %d shares, got %d", n, len(res.Shares))
	}

	// Reconstruct s1 and u from ANY t shares; check T = A·s1 + B·u.
	subset := make([]int, tt)
	for i := range tt {
		subset[i] = i
	}
	s1 := reconstruct(profile.Ring, res.Shares, subset, profile.L)
	u := reconstruct(profile.Ring, res.Blinds, subset, profile.L)
	Tprime := recomputeT(profile, s1, u)
	if ring.ConstantTimeVecEqual(Tprime, res.GroupKey.T) != 1 {
		t.Fatal("group key root T != A·s1 + B·u — DKG produced shares of the wrong secret")
	}

	// Reconstruct from a DIFFERENT t-subset; must yield the same s1 (consistency
	// of the degree-(t-1) sharing).
	if n > tt {
		subset2 := make([]int, tt)
		for i := range tt {
			subset2[i] = n - 1 - i
		}
		s1b := reconstruct(profile.Ring, res.Shares, subset2, profile.L)
		if ring.ConstantTimeVecEqual(s1, s1b) != 1 {
			t.Fatal("two t-subsets reconstructed different s1 — sharing inconsistent")
		}
	}
	return res
}

func TestRunDKG_Ringtail_Correct(t *testing.T) {
	p, err := ring.Ringtail()
	if err != nil {
		t.Fatal(err)
	}
	runCorrect(t, p, 5, 3)
}

func TestRunDKG_MLDSA_Correct(t *testing.T) {
	p, err := ring.MLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	res := runCorrect(t, p, 5, 3)
	// ML-DSA finalize must also expose t0 (Aux) for the signer's hint path.
	if res.GroupKey.Aux == nil || len(res.GroupKey.Aux) != p.K {
		t.Fatal("ML-DSA group key must carry t0 (Aux)")
	}
}

// TestRunDKG_Deterministic checks the transcript hash is stable given the same
// inputs (same identities, same RNG stream).
func TestRunDKG_VariousShapes(t *testing.T) {
	p, _ := ring.Ringtail()
	for _, sh := range []struct{ n, t int }{{2, 1}, {3, 2}, {7, 4}} {
		t.Run("ringtail", func(t *testing.T) { runCorrect(t, p, sh.n, sh.t) })
	}
}
