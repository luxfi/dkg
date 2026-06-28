// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import (
	"testing"

	"github.com/luxfi/dkg/ring"
)

// partition_general_test.go exercises the GENERAL Algorithm-6 balanced partition
// (balancedPartition / the N>6 path of RSSRecover) that unblocks the owner's
// fault-tolerant default committees n=8,t=7 and n=16,t=14. It pins three things:
//   - VALIDITY: every C(N,M) subset is covered exactly once, each subset assigned
//     to one of its members (so a holder always has the share it must sum);
//   - OPTIMAL BALANCE: max per-signer load == ⌈C/T⌉, the information-theoretic
//     floor — zero slack, matching the N≤6 reference table's balance;
//   - REFERENCE PARITY: for N≤6 the general partition is equally valid+balanced
//     as the hardcoded canonicalSharing table it generalises.

// validatePartition asserts a partition is structurally valid for (active,T,N)
// and returns its maximum per-signer load. T == len(active) is assumed.
func validatePartition(t *testing.T, part [][]uint64, active []int, tt, n int) int {
	t.Helper()
	full := EnumerateSubsets(tt, n)
	want := make(map[uint64]bool, len(full))
	for _, m := range full {
		want[m] = true
	}
	if len(part) != tt {
		t.Fatalf("(T=%d,N=%d) active=%v: partition length %d, want T=%d", tt, n, active, len(part), tt)
	}
	seen := make(map[uint64]bool, len(full))
	maxLoad := 0
	for j, shares := range part {
		if len(shares) > maxLoad {
			maxLoad = len(shares)
		}
		signer := active[j]
		for _, mask := range shares {
			if seen[mask] {
				t.Fatalf("(T=%d,N=%d) active=%v: subset 0b%b assigned twice", tt, n, active, mask)
			}
			seen[mask] = true
			if !want[mask] {
				t.Fatalf("(T=%d,N=%d) active=%v: assigned non-existent subset 0b%b", tt, n, active, mask)
			}
			if mask&(uint64(1)<<uint(signer)) == 0 {
				t.Fatalf("(T=%d,N=%d): signer %d assigned subset 0b%b it is NOT a member of", tt, n, signer, mask)
			}
		}
	}
	if len(seen) != len(full) {
		t.Fatalf("(T=%d,N=%d) active=%v: covered %d subsets, want %d", tt, n, active, len(seen), len(full))
	}
	return maxLoad
}

// ceilDiv returns ⌈a/b⌉, the optimal (information-theoretic floor) max-load.
func ceilDiv(a, b int) int { return (a + b - 1) / b }

// TestBalancedPartitionOwnerTargets is the headline partition proof: the
// fault-tolerant DEFAULT committees produce a valid, OPTIMALLY balanced partition
// through the wired entry point (RSSRecover, the Reconstruct/Sign path) — the
// precondition that was missing and made them fail-closed at N>6.
func TestBalancedPartitionOwnerTargets(t *testing.T) {
	for _, c := range []struct{ tt, n int }{
		{7, 8},   // owner default (M=2, C(8,2)=28, optimal max-load 4)
		{14, 16}, // owner fault-tolerant (M=3, C(16,3)=560, optimal max-load 40)
		{8, 8},   // T==N base case at N>6 (singletons)
		{16, 16}, // T==N base case at large N
	} {
		c := c
		full := NumSubsets(c.tt, c.n)
		opt := ceilDiv(full, c.tt)
		var sets [][]int
		if c.n <= 8 {
			sets = allActiveSets(c.n, c.tt) // exhaustive when cheap
		} else {
			sets = activeSets(c.tt, c.n) // canonical / top / spread
		}
		for _, active := range sets {
			part, err := RSSRecover(active, c.tt, c.n)
			if err != nil {
				t.Fatalf("RSSRecover(T=%d,N=%d,active=%v): %v", c.tt, c.n, active, err)
			}
			maxLoad := validatePartition(t, part, active, c.tt, c.n)
			if maxLoad != opt {
				t.Errorf("(T=%d,N=%d) active=%v: max-load %d, want OPTIMAL ⌈C/T⌉=%d (C=%d)",
					c.tt, c.n, active, maxLoad, opt, full)
			}
		}
	}
}

// TestBalancedPartitionSweep proves validity + OPTIMAL balance (max-load ==
// ⌈C/T⌉, zero slack) for every norm-admissible committee across a representative
// range, over several active sets, through the general partition. The optimum is
// the information-theoretic floor in every case — the max-flow assignment is
// Algorithm 6's optimal partition, not an approximation.
func TestBalancedPartitionSweep(t *testing.T) {
	for n := 2; n <= 18; n++ {
		for tt := 2; tt <= n; tt++ {
			if ValidateCommittee(tt, n) != nil {
				continue // skip committees the norm bound rejects
			}
			opt := ceilDiv(NumSubsets(tt, n), tt)
			for _, active := range sweepActiveSets(n, tt) {
				part, err := balancedPartition(active, tt, n)
				if err != nil {
					t.Fatalf("balancedPartition(T=%d,N=%d,active=%v): %v", tt, n, active, err)
				}
				if ml := validatePartition(t, part, active, tt, n); ml != opt {
					t.Errorf("(T=%d,N=%d) active=%v: max-load %d != optimal ⌈C/T⌉=%d", tt, n, active, ml, opt)
				}
			}
		}
	}
}

// TestBalancedPartitionMatchesReferenceTable cross-checks the general partition
// against the byte-for-byte reference table (canonicalSharing) for N≤6, T<N, on
// the canonical active set {0..T−1} the table is stated for. The contract is
// EQUAL validity + balance (an optimum need not be unique, so the flow may pick a
// different but equally optimal assignment); exact coincidences are logged.
func TestBalancedPartitionMatchesReferenceTable(t *testing.T) {
	exact, total := 0, 0
	for n := 2; n <= referenceMaxN; n++ {
		for tt := 2; tt < n; tt++ { // T<N only; T==N has no table entry
			table, ok := canonicalSharing[[2]int{tt, n}]
			if !ok {
				t.Fatalf("(T=%d,N=%d): expected a reference table entry", tt, n)
			}
			canon := make([]int, tt)
			for i := range canon {
				canon[i] = i
			}
			gen, err := balancedPartition(canon, tt, n)
			if err != nil {
				t.Fatalf("balancedPartition(T=%d,N=%d): %v", tt, n, err)
			}
			genLoad := validatePartition(t, gen, canon, tt, n)
			tableLoad := 0
			for _, s := range table {
				if len(s) > tableLoad {
					tableLoad = len(s)
				}
			}
			if genLoad != tableLoad {
				t.Errorf("(T=%d,N=%d): general max-load %d != reference table max-load %d", tt, n, genLoad, tableLoad)
			}
			total++
			if partitionsEqualAsSets(gen, table) {
				exact++
			}
		}
	}
	t.Logf("reference cross-check: %d/%d (T,N) match the table exactly; all equally valid + optimally balanced", exact, total)
}

// TestBalancedPartitionDeterministic pins that the general partition is a pure
// function of (active,T,N): byte-identical on repeat. A no-reconstruct
// aggregation requires every honest signer/auditor to derive the identical
// assignment so each subset's short secret is summed exactly once.
func TestBalancedPartitionDeterministic(t *testing.T) {
	cases := []struct {
		tt, n  int
		active []int
	}{
		{7, 8, []int{0, 1, 2, 3, 4, 5, 6}},
		{7, 8, []int{1, 2, 3, 4, 5, 6, 7}},
		{7, 8, []int{0, 1, 2, 3, 4, 5, 7}}, // inactive party in the middle
		{14, 16, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}},
	}
	for _, c := range cases {
		a, err := balancedPartition(c.active, c.tt, c.n)
		if err != nil {
			t.Fatalf("(T=%d,N=%d): %v", c.tt, c.n, err)
		}
		b, err := balancedPartition(c.active, c.tt, c.n)
		if err != nil {
			t.Fatalf("(T=%d,N=%d): %v", c.tt, c.n, err)
		}
		for j := range a {
			if len(a[j]) != len(b[j]) {
				t.Fatalf("(T=%d,N=%d) slot %d length mismatch %d != %d", c.tt, c.n, j, len(a[j]), len(b[j]))
			}
			for k := range a[j] {
				if a[j][k] != b[j][k] {
					t.Fatalf("(T=%d,N=%d) slot %d order mismatch at %d", c.tt, c.n, j, k)
				}
			}
		}
	}
}

// TestReconstructOwnerTargetsBeyond6 proves the FULL dealerless keygen →
// reconstruct path now works for the fault-tolerant defaults (N>6, T<N), which
// the missing partition previously blocked: every T-quorum reconstructs the
// IDENTICAL short (s1,s2), it reproduces the published no-reconstruct group key,
// and the secret stays within the wall-beating C(N,M)·η bound. This is the
// dkg-level unblock the pulsar stock-circl sign test (Step 3) builds on.
func TestReconstructOwnerTargetsBeyond6(t *testing.T) {
	prof, err := ring.MLDSA65()
	if err != nil {
		t.Fatalf("MLDSA65 profile: %v", err)
	}
	r := prof.Ring
	for _, c := range []struct{ tt, n int }{{7, 8}, {14, 16}} {
		keys, err := Generate(prof, c.tt, c.n, seeds(c.n))
		if err != nil {
			t.Fatalf("(T=%d,N=%d) Generate: %v", c.tt, c.n, err)
		}
		canon := make([]int, c.tt)
		for i := range canon {
			canon[i] = i
		}
		s1, s2, err := Reconstruct(keys, canon)
		if err != nil {
			t.Fatalf("(T=%d,N=%d) Reconstruct: %v", c.tt, c.n, err)
		}
		// Reconstructed-secret key == published no-reconstruct key.
		if !vecEqual(RecomputeT(prof, s1, s2), keys.Group.T) {
			t.Fatalf("(T=%d,N=%d): A·s1+s2 (reconstructed) != published T (no-reconstruct)", c.tt, c.n)
		}
		// Short secret within the wall-beating bound.
		bound := MaxSecretNorm(c.tt, c.n, prof.Eta)
		if n1, n2 := InfNorm(r, s1), InfNorm(r, s2); n1 > bound || n2 > bound {
			t.Fatalf("(T=%d,N=%d): ‖s1‖∞=%d ‖s2‖∞=%d exceed C(N,M)·η=%d", c.tt, c.n, n1, n2, bound)
		}
		// Several distinct T-quorums reconstruct the IDENTICAL secret.
		var quorums [][]int
		if c.n <= 8 {
			quorums = allActiveSets(c.n, c.tt) // all 8 for n=8,t=7
		} else {
			quorums = activeSets(c.tt, c.n) // canon / top / spread for n=16,t=14
		}
		for _, active := range quorums {
			as1, as2, err := Reconstruct(keys, active)
			if err != nil {
				t.Fatalf("(T=%d,N=%d) active=%v Reconstruct: %v", c.tt, c.n, active, err)
			}
			if !vecEqual(as1, s1) || !vecEqual(as2, s2) {
				t.Fatalf("(T=%d,N=%d): quorum %v reconstructed a DIFFERENT secret", c.tt, c.n, active)
			}
		}
	}
}

// sweepActiveSets returns representative size-T active sets for the sweep:
// exhaustive when cheap (N≤8), else canonical / top / spread.
func sweepActiveSets(n, t int) [][]int {
	if n <= 8 {
		return allActiveSets(n, t)
	}
	return activeSets(t, n)
}

// partitionsEqualAsSets compares two partitions slot-by-slot, treating each
// signer's assigned-subset list as a set (order-independent). Both arguments are
// for the same active set, so slot j corresponds to the same signer in both.
func partitionsEqualAsSets(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for j := range a {
		if !sameSet(a[j], b[j]) {
			return false
		}
	}
	return true
}

func sameSet(x, y []uint64) bool {
	if len(x) != len(y) {
		return false
	}
	count := make(map[uint64]int, len(x))
	for _, v := range x {
		count[v]++
	}
	for _, v := range y {
		count[v]--
		if count[v] < 0 {
			return false
		}
	}
	return true
}
