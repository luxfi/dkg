// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import (
	"sort"
	"testing"
)

// TestRSSRecoverCoversAllSubsetsOnce checks the core balanced-partition
// invariant for every admissible (T,N) and every active set: the union of
// assigned subsets equals exactly the full subset list, with no duplicates,
// and each signer belongs to every subset it is assigned.
func TestRSSRecoverCoversAllSubsetsOnce(t *testing.T) {
	for n := 2; n <= referenceMaxN; n++ {
		for tt := 2; tt <= n; tt++ {
			full := EnumerateSubsets(tt, n)
			wantSet := map[uint64]bool{}
			for _, m := range full {
				wantSet[m] = true
			}
			// Test several active sets, including non-canonical ones.
			for _, active := range activeSets(tt, n) {
				part, err := RSSRecover(active, tt, n)
				if err != nil {
					t.Fatalf("(T=%d,N=%d) active=%v: %v", tt, n, active, err)
				}
				if len(part) != tt {
					t.Fatalf("(T=%d,N=%d): partition length %d, want T=%d", tt, n, len(part), tt)
				}
				seen := map[uint64]bool{}
				for j, shares := range part {
					signer := active[j]
					for _, mask := range shares {
						if seen[mask] {
							t.Fatalf("(T=%d,N=%d) active=%v: subset 0b%b assigned twice", tt, n, active, mask)
						}
						seen[mask] = true
						if !wantSet[mask] {
							t.Fatalf("(T=%d,N=%d) active=%v: assigned non-existent subset 0b%b", tt, n, active, mask)
						}
						if mask&(uint64(1)<<uint(signer)) == 0 {
							t.Fatalf("(T=%d,N=%d): signer %d assigned subset 0b%b it is not a member of", tt, n, signer, mask)
						}
					}
				}
				if len(seen) != len(full) {
					t.Fatalf("(T=%d,N=%d) active=%v: covered %d subsets, want %d", tt, n, active, len(seen), len(full))
				}
			}
		}
	}
}

func TestRSSRecoverRejectsBadActiveSets(t *testing.T) {
	if _, err := RSSRecover([]int{0, 0}, 2, 3); err == nil {
		t.Fatal("duplicate signer id accepted")
	}
	if _, err := RSSRecover([]int{2, 1}, 2, 3); err == nil {
		t.Fatal("unsorted active set accepted")
	}
	if _, err := RSSRecover([]int{0, 3}, 2, 3); err == nil {
		t.Fatal("out-of-range signer accepted")
	}
	if _, err := RSSRecover([]int{0}, 2, 3); err == nil {
		t.Fatal("wrong-length active set accepted")
	}
	if _, err := RSSRecover([]int{0, 1, 2}, 2, 64); err == nil {
		t.Fatal("N>MaxBitmaskParties accepted")
	}
	if _, err := RSSRecover([]int{0, 1, 2, 3, 4}, 12, 16); err == nil {
		t.Fatal("norm-budget-blown committee accepted")
	}
}

// activeSets returns a few representative size-T sorted active sets for (T,N):
// the canonical {0..T-1}, the top {N-T..N-1}, and (when room) a spread set.
func activeSets(t, n int) [][]int {
	out := [][]int{}
	canon := make([]int, t)
	for i := range canon {
		canon[i] = i
	}
	out = append(out, canon)
	top := make([]int, t)
	for i := range top {
		top[i] = n - t + i
	}
	if !equalInts(top, canon) {
		out = append(out, top)
	}
	if n-t >= 1 && t >= 2 {
		spread := map[int]bool{0: true, n - 1: true}
		i := 1
		for len(spread) < t {
			spread[i] = true
			i++
		}
		s := make([]int, 0, t)
		for k := range spread {
			s = append(s, k)
		}
		sort.Ints(s)
		if len(s) == t && !equalInts(s, canon) && !equalInts(s, top) {
			out = append(out, s)
		}
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
