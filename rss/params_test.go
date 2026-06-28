// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import "testing"

// TestValidateCommittee pins the exact Mithril (n,t) viability bound:
// 2 ≤ T ≤ N ≤ 6. Anything else is fail-closed.
func TestValidateCommittee(t *testing.T) {
	valid := [][2]int{
		{2, 2}, {2, 3}, {3, 3}, {2, 4}, {3, 4}, {4, 4},
		{2, 5}, {3, 5}, {4, 5}, {5, 5},
		{2, 6}, {3, 6}, {4, 6}, {5, 6}, {6, 6},
	}
	for _, tn := range valid {
		if err := ValidateCommittee(tn[0], tn[1]); err != nil {
			t.Fatalf("ValidateCommittee(%d,%d) rejected a viable committee: %v", tn[0], tn[1], err)
		}
	}
	if len(valid) != 15 {
		t.Fatalf("expected 15 valid (T,N) pairs, got %d", len(valid))
	}
	bad := [][2]int{{1, 2}, {3, 2}, {2, 7}, {7, 7}, {0, 0}, {2, 1}}
	for _, tn := range bad {
		if err := ValidateCommittee(tn[0], tn[1]); err == nil {
			t.Fatalf("ValidateCommittee(%d,%d) admitted a non-viable committee", tn[0], tn[1])
		}
	}
}

// TestBinomial cross-checks against the reference implementation's test vectors.
func TestBinomial(t *testing.T) {
	cases := []struct {
		n, k, want int
	}{
		{3, 2, 3}, {4, 2, 6}, {6, 3, 20}, {6, 5, 6}, {5, 0, 1}, {5, 5, 1}, {6, 7, 0},
	}
	for _, c := range cases {
		if got := Binomial(c.n, c.k); got != c.want {
			t.Errorf("Binomial(%d,%d)=%d, want %d", c.n, c.k, got, c.want)
		}
	}
}

// TestNumSubsets pins C(N, N−T+1) against the reference's num_subsets vectors.
func TestNumSubsets(t *testing.T) {
	cases := []struct {
		t, n, want int
	}{
		{2, 3, 3}, // C(3,2)=3
		{3, 4, 6}, // C(4,2)=6
		{2, 6, 6}, // C(6,5)=6
		{4, 6, 20}, // C(6,3)=20 — the maximum over the admissible range
		{6, 6, 6}, // C(6,1)=6 (singletons)
	}
	maxSubsets := 0
	for _, c := range cases {
		if got := NumSubsets(c.t, c.n); got != c.want {
			t.Errorf("NumSubsets(T=%d,N=%d)=%d, want %d", c.t, c.n, got, c.want)
		}
	}
	// The maximum subset count over all admissible (T,N) is C(6,3)=20.
	for n := 2; n <= MaxParties; n++ {
		for tt := 2; tt <= n; tt++ {
			if s := NumSubsets(tt, n); s > maxSubsets {
				maxSubsets = s
			}
		}
	}
	if maxSubsets != 20 {
		t.Fatalf("max subset count over admissible range = %d, want 20 (at T=4,N=6)", maxSubsets)
	}
}

// TestEnumerateSubsets checks count, popcount, and the dealerless invariant:
// no single party is a member of every subset (so no party holds the full key).
func TestEnumerateSubsets(t *testing.T) {
	for n := 2; n <= MaxParties; n++ {
		for tt := 2; tt <= n; tt++ {
			subsets := EnumerateSubsets(tt, n)
			if len(subsets) != NumSubsets(tt, n) {
				t.Fatalf("(T=%d,N=%d): got %d subsets, want %d", tt, n, len(subsets), NumSubsets(tt, n))
			}
			m := SubsetSize(tt, n)
			for _, mask := range subsets {
				if pc := popcount(mask); pc != m {
					t.Fatalf("(T=%d,N=%d): subset 0b%b popcount %d, want M=%d", tt, n, mask, pc, m)
				}
			}
			// Dealerless invariant: every party is missing from at least one subset.
			for party := 0; party < n; party++ {
				held := 0
				for _, mask := range subsets {
					if mask&(uint64(1)<<uint(party)) != 0 {
						held++
					}
				}
				if held != SharesPerParty(tt, n) {
					t.Fatalf("(T=%d,N=%d): party %d holds %d shares, want C(N-1,M-1)=%d",
						tt, n, party, held, SharesPerParty(tt, n))
				}
				if held == len(subsets) {
					t.Fatalf("(T=%d,N=%d): party %d is in EVERY subset — not dealerless", tt, n, party)
				}
			}
		}
	}
}

func popcount(x uint64) int {
	c := 0
	for x != 0 {
		x &= x - 1
		c++
	}
	return c
}
