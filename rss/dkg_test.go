// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/luxfi/dkg/ring"
)

func mldsaProfile(t *testing.T) *ring.Profile {
	t.Helper()
	prof, err := ring.MLDSA65()
	if err != nil {
		t.Fatalf("MLDSA65 profile: %v", err)
	}
	return prof
}

func seeds(n int) [][]byte {
	ps := make([][]byte, n)
	for i := range ps {
		s := make([]byte, 32)
		for j := range s {
			s[j] = byte(17*i + 3*j + 1)
		}
		ps[i] = s
	}
	return ps
}

func allActiveSets(n, t int) [][]int { // all sorted size-t subsets of {0..n-1}
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == t {
			cp := append([]int(nil), cur...)
			out = append(out, cp)
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(0, nil)
	return out
}

// TestGenerateAllCommittees is the headline keygen proof. For every admissible
// (T,N) it asserts:
//   - the no-reconstruct group key (built from PUBLIC per-subset commitments)
//     equals the key recomputed from the reconstructed secret: A·s1+s2 == T;
//   - Power2Round(T) == published t1;
//   - the reconstructed (s1,s2) are SHORT: ‖·‖∞ ≤ C(N,M)·η — the wall-beating
//     bound — and that bound is ≪ q/2 (the large-blinding vss s2);
//   - ANY T-quorum reconstructs the IDENTICAL (s1,s2) (well-defined key);
//   - DEALERLESS: no single party holds all subsets, and no T−1 parties cover
//     all subsets (so < T cannot reconstruct).
func TestGenerateAllCommittees(t *testing.T) {
	prof := mldsaProfile(t)
	r := prof.Ring
	eta := prof.Eta
	q := r.Q()

	for n := 2; n <= MaxParties; n++ {
		for tt := 2; tt <= n; tt++ {
			keys, err := Generate(prof, tt, n, seeds(n))
			if err != nil {
				t.Fatalf("(T=%d,N=%d) Generate: %v", tt, n, err)
			}

			// Reconstruct from the canonical quorum and cross-check the key.
			canon := make([]int, tt)
			for i := range canon {
				canon[i] = i
			}
			s1, s2, err := Reconstruct(keys, canon)
			if err != nil {
				t.Fatalf("(T=%d,N=%d) Reconstruct: %v", tt, n, err)
			}

			// No-reconstruct key == reconstructed-secret key.
			tRecomputed := RecomputeT(prof, s1, s2)
			if !vecEqual(tRecomputed, keys.Group.T) {
				t.Fatalf("(T=%d,N=%d): A·s1+s2 (reconstructed) != T (no-reconstruct)", tt, n)
			}
			t1Re, _ := ring.Power2RoundVec(r, tRecomputed)
			if !vecEqual(t1Re, keys.Group.T1) {
				t.Fatalf("(T=%d,N=%d): Power2Round(reconstructed T) != published t1", tt, n)
			}

			// Wall-beating bound: short secret, ≪ q/2.
			bound := MaxSecretNorm(tt, n, eta)
			n1, n2 := InfNorm(r, s1), InfNorm(r, s2)
			if n1 > bound || n2 > bound {
				t.Fatalf("(T=%d,N=%d): ‖s1‖∞=%d ‖s2‖∞=%d exceed C(N,M)·η=%d", tt, n, n1, n2, bound)
			}
			if bound >= q/8 {
				t.Fatalf("(T=%d,N=%d): bound %d not ≪ q/2=%d — not clearly short", tt, n, bound, q/2)
			}

			// Any T-quorum reconstructs the IDENTICAL short secret.
			for _, active := range allActiveSets(n, tt) {
				as1, as2, err := Reconstruct(keys, active)
				if err != nil {
					t.Fatalf("(T=%d,N=%d) active=%v Reconstruct: %v", tt, n, active, err)
				}
				if !vecEqual(as1, s1) || !vecEqual(as2, s2) {
					t.Fatalf("(T=%d,N=%d): quorum %v reconstructed a DIFFERENT secret", tt, n, active)
				}
			}

			assertDealerless(t, keys, tt, n)
		}
	}
}

// assertDealerless checks the structural dealerless guarantee: every party is
// missing ≥1 subset, and no T−1 parties together cover all subsets (so fewer
// than T cannot reconstruct the key).
func assertDealerless(t *testing.T, keys *Keys, tt, n int) {
	t.Helper()
	full := EnumerateSubsets(tt, n)
	// No single party holds all subsets.
	for _, p := range keys.Parties {
		if len(p.Held) == len(full) {
			t.Fatalf("(T=%d,N=%d): party %d holds ALL %d subsets — not dealerless", tt, n, p.ID, len(full))
		}
	}
	// No (T-1)-coalition covers all subsets.
	for _, coalition := range allActiveSets(n, tt-1) {
		covered := map[uint64]bool{}
		for _, id := range coalition {
			for mask := range keys.Parties[id].Held {
				covered[mask] = true
			}
		}
		if len(covered) == len(full) {
			t.Fatalf("(T=%d,N=%d): coalition %v of size T-1 covers ALL subsets — threshold broken", tt, n, coalition)
		}
	}
}

// TestGenerateDeterministic pins that the dealerless DKG is a deterministic
// function of (profile, T, N, party seeds): honest parties recompute an
// identical key, and a chain can KAT it.
func TestGenerateDeterministic(t *testing.T) {
	prof := mldsaProfile(t)
	k1, err := Generate(prof, 3, 5, seeds(5))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Generate(prof, 3, 5, seeds(5))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.Group.Rho, k2.Group.Rho) || !vecEqual(k1.Group.T1, k2.Group.T1) {
		t.Fatal("Generate is not deterministic")
	}
}

func TestGenerateRejectsBadCommittee(t *testing.T) {
	prof := mldsaProfile(t)
	for _, tn := range [][2]int{{1, 2}, {3, 2}, {2, 7}, {7, 7}} {
		if _, err := Generate(prof, tn[0], tn[1], seeds(maxInt(tn[1], 7))); err == nil {
			t.Fatalf("Generate admitted non-viable committee (T=%d,N=%d)", tn[0], tn[1])
		}
	}
}

func vecEqual(a, b ring.Vector) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(polyBytes(a[i]), polyBytes(b[i])) {
			return false
		}
	}
	return true
}

func polyBytes(p ring.Poly) []byte {
	var buf bytes.Buffer
	for _, c := range p.Coeffs[0] {
		fmt.Fprintf(&buf, "%d,", c)
	}
	return buf.Bytes()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
