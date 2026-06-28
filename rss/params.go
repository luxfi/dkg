// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import "fmt"

// MaxParties is the largest committee size the Mithril RSS construction admits.
// Beyond N=6 the number of replicated subsets C(N,N−T+1) and the local
// rejection-sampling cost make the scheme impractical (ePrint 2026/013, §"up to
// 6 parties"; the reference implementation caps MAX_PARTIES at 6). The Pulsar
// signing committee is deliberately bounded by this value; broad security comes
// from Avalanche subsampling, not from a large signing committee.
const MaxParties = 6

// ErrCommittee is returned for any (T, N) outside the Mithril-viable range
// 2 ≤ T ≤ N ≤ MaxParties. It is fail-closed: an out-of-range committee never
// silently degrades to a weaker mode.
type ErrCommittee struct {
	T, N int
}

func (e *ErrCommittee) Error() string {
	return fmt.Sprintf("rss: committee (T=%d, N=%d) outside Mithril-viable range "+
		"2 ≤ T ≤ N ≤ %d (RSS subset count C(N,N−T+1) and local rejection cost "+
		"make larger committees impractical)", e.T, e.N, MaxParties)
}

// ValidateCommittee enforces the exact (n, t) viability bound. This is the one
// place the Mithril committee constraint is checked; every entry point routes
// through it so the bound cannot be bypassed.
func ValidateCommittee(t, n int) error {
	if t < 2 || t > n || n > MaxParties {
		return &ErrCommittee{T: t, N: n}
	}
	return nil
}

// Binomial returns C(n, k) using the multiplicative formula with the smaller of
// k and n−k for numerical stability. Returns 0 when k > n.
func Binomial(n, k int) int {
	if k < 0 || k > n {
		return 0
	}
	if k == 0 || k == n {
		return 1
	}
	if k > n-k {
		k = n - k
	}
	result := 1
	for i := 0; i < k; i++ {
		result = result * (n - i) / (i + 1)
	}
	return result
}

// SubsetSize returns M = N − T + 1, the cardinality of every RSS subset.
func SubsetSize(t, n int) int { return n - t + 1 }

// NumSubsets returns the number of RSS subsets C(N, N−T+1) for an (N, T)
// threshold — the count of distinct short secret shares the key is split into.
func NumSubsets(t, n int) int { return Binomial(n, SubsetSize(t, n)) }

// SharesPerParty returns C(N−1, M−1) = C(N−1, N−T), the number of subset shares
// each party holds (every M-subset that contains it). This bounds a party's
// local secret material: ‖s_{·,i}^hold‖∞ ≤ SharesPerParty·η.
func SharesPerParty(t, n int) int { return Binomial(n-1, SubsetSize(t, n)-1) }

// EnumerateSubsets returns the bitmasks of all M-subsets of {0,…,N−1} in
// ascending order, where M = N − T + 1 and bit i set means party i ∈ subset.
// Uses Gosper's hack to walk fixed-popcount bitmasks, matching the reference
// implementation's subset ordering exactly. Returns nil for an invalid (T, N).
func EnumerateSubsets(t, n int) []uint64 {
	if t < 2 || t > n || n > 63 {
		return nil
	}
	m := SubsetSize(t, n)
	out := make([]uint64, 0, NumSubsets(t, n))
	mask := uint64(1)<<uint(m) - 1 // lexicographically smallest m-popcount mask
	limit := uint64(1) << uint(n)
	for mask < limit {
		out = append(out, mask)
		// Gosper's hack: next bitmask with the same popcount.
		c := mask & (^mask + 1) // lowest set bit
		if c == 0 {
			break
		}
		r := mask + c
		mask = (((r ^ mask) >> 2) / c) | r
	}
	return out
}

// SubsetMembers expands a subset bitmask into its sorted party indices.
func SubsetMembers(mask uint64, n int) []int {
	members := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if mask&(uint64(1)<<uint(i)) != 0 {
			members = append(members, i)
		}
	}
	return members
}
