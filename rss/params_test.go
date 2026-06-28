// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import "testing"

// referenceMaxN is the largest N covered by the byte-for-byte reference
// partition table (canonicalSharing, up to N=6). The exhaustive reference-parity
// tests iterate this range; the admission bound itself reaches much further and
// is exercised separately in TestValidateCommittee.
const referenceMaxN = 6

// TestValidateCommittee pins the per-(N,T) norm-viability bound
// τ·C(N,N−T+1)·η < γ2 — the FIX that replaces the old flat N≤6 cap. The owner's
// target sets must be admitted; the over-budget set must be rejected.
func TestValidateCommittee(t *testing.T) {
	// admit: τ·C·η computed and asserted < γ2 = 261888.
	admit := []struct {
		t, n     int
		wantUsed uint64
	}{
		{7, 8, 5488},     // M=2, C(8,2)=28  → 49·28·4   (owner target; 48× margin)
		{8, 8, 1568},     // M=1, C(8,1)=8   → 49·8·4    (owner target)
		{14, 16, 109760}, // M=3, C(16,3)=560→ 49·560·4  (owner target; tight, 2.4×)
		{4, 6, 3920},     // M=3, C(6,3)=20  → 49·20·4   (old max-subset case)
		{6, 6, 1176},     // M=1, C(6,1)=6
		{2, 2, 392},      // M=1, C(2,1)=2   smallest committee
		{16, 16, 3136},   // M=1, C(16,1)=16 full unanimity, large N
		{31, 32, 97216},  // M=2, C(32,2)=496 — large N still viable at high T
	}
	for _, c := range admit {
		if err := ValidateCommittee(c.t, c.n); err != nil {
			t.Fatalf("ValidateCommittee(T=%d,N=%d) rejected a viable committee: %v", c.t, c.n, err)
		}
		used, margin := HintBudgetUsage(c.t, c.n)
		if used != c.wantUsed {
			t.Fatalf("HintBudgetUsage(T=%d,N=%d) used=%d, want %d", c.t, c.n, used, c.wantUsed)
		}
		if used >= margin {
			t.Fatalf("(T=%d,N=%d) admitted but used=%d ≥ margin=%d", c.t, c.n, used, margin)
		}
	}

	// reject: structural OR norm-budget blown.
	reject := [][2]int{
		{12, 16}, // M=5, C(16,5)=4368 → 49·4368·4 = 856128 > γ2 — hint budget blown
		{1, 2},   // T<2 (not a real threshold)
		{3, 2},   // T>N
		{0, 0},   // degenerate
		{2, 1},   // T>N
		{2, 64},  // N over the uint64 bitmask ceiling
		{10, 20}, // M=11, C(20,11)=167960 — far over budget
	}
	for _, tn := range reject {
		if err := ValidateCommittee(tn[0], tn[1]); err == nil {
			t.Fatalf("ValidateCommittee(T=%d,N=%d) admitted a non-viable committee", tn[0], tn[1])
		}
	}
}

// TestViabilityBoundary pins the exact admit/reject crossover of the norm bound:
// the largest viable subset count is ⌊γ2/(τη)⌋ = 1336 (used=261856 < γ2);
// 1337 subsets (used=262052 ≥ γ2) is the first rejected count.
func TestViabilityBoundary(t *testing.T) {
	if maxViableSubsets != 1336 {
		t.Fatalf("maxViableSubsets=%d, want 1336", maxViableSubsets)
	}
	if used := uint64(mldsaTau * 1336 * mldsaEta); used >= mldsaGamma2 {
		t.Fatalf("C=1336 should clear γ2: used=%d ≥ %d", used, mldsaGamma2)
	}
	if used := uint64(mldsaTau * 1337 * mldsaEta); used < mldsaGamma2 {
		t.Fatalf("C=1337 should blow γ2: used=%d < %d", used, mldsaGamma2)
	}
}

// TestBinomial cross-checks against the reference implementation's test vectors.
func TestBinomial(t *testing.T) {
	cases := []struct {
		n, k, want int
	}{
		{3, 2, 3}, {4, 2, 6}, {6, 3, 20}, {6, 5, 6}, {5, 0, 1}, {5, 5, 1}, {6, 7, 0},
		{8, 2, 28}, {16, 3, 560}, {16, 5, 4368}, // the owner's-set subset counts
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
		{2, 3, 3},     // C(3,2)=3
		{3, 4, 6},     // C(4,2)=6
		{2, 6, 6},     // C(6,5)=6
		{4, 6, 20},    // C(6,3)=20 — the max over the N≤6 reference range
		{6, 6, 6},     // C(6,1)=6 (singletons)
		{7, 8, 28},    // owner target
		{14, 16, 560}, // owner target
	}
	for _, c := range cases {
		if got := NumSubsets(c.t, c.n); got != c.want {
			t.Errorf("NumSubsets(T=%d,N=%d)=%d, want %d", c.t, c.n, got, c.want)
		}
	}
	// Over the N≤6 reference range the maximum subset count is C(6,3)=20.
	maxSubsets := 0
	for n := 2; n <= referenceMaxN; n++ {
		for tt := 2; tt <= n; tt++ {
			if s := NumSubsets(tt, n); s > maxSubsets {
				maxSubsets = s
			}
		}
	}
	if maxSubsets != 20 {
		t.Fatalf("max subset count over N≤6 range = %d, want 20 (at T=4,N=6)", maxSubsets)
	}
}

// TestEnumerateSubsets checks count, popcount, and the dealerless invariant: no
// single party is a member of every subset (so no party holds the full key). It
// runs over every committee admitted by the norm bound up to a representative N.
func TestEnumerateSubsets(t *testing.T) {
	for n := 2; n <= 16; n++ {
		for tt := 2; tt <= n; tt++ {
			if ValidateCommittee(tt, n) != nil {
				continue // skip committees the norm bound rejects
			}
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
				if held == len(subsets) && tt >= 2 {
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
