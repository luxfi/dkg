// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import "fmt"

// partition.go — the balanced reconstruction partition (ePrint 2026/013,
// Algorithm 6 / RSSRecover). Given an active signer set of size T, it assigns
// every one of the C(N,N−T+1) subset shares to EXACTLY ONE active signer, so a
// reconstruction (or a threshold-signing aggregation) sums each subset's short
// secret once and only once — never double-counted, never dropped. The
// assignment minimises the maximum number of shares any one signer must touch.
//
// Subsets are bitmasks (bit i ⇔ party i ∈ subset), matching EnumerateSubsets
// and the reference Go/Rust implementations byte-for-byte.

// canonicalSharing holds, for each (T, N) with T < N, the optimal partition for
// the CANONICAL active set {0,1,…,T−1}: element j is the list of subset
// bitmasks assigned to canonical signer j. Lifted verbatim from the reference
// implementation (partition.rs / Algorithm 6). The T == N case is handled
// separately (each party gets its own singleton).
var canonicalSharing = map[[2]int][][]uint64{
	{2, 3}: {{3, 5}, {6}},
	{2, 4}: {{11, 13}, {7, 14}},
	{3, 4}: {{3, 9}, {6, 10}, {12, 5}},
	{2, 5}: {{27, 29, 23}, {30, 15}},
	{3, 5}: {{25, 11, 19, 13}, {7, 14, 22, 26}, {28, 21}},
	{4, 5}: {{3, 9, 17}, {6, 10, 18}, {12, 5, 20}, {24}},
	{2, 6}: {{61, 47, 55}, {62, 31, 59}},
	{3, 6}: {{27, 23, 43, 57, 39}, {51, 58, 46, 30, 54}, {45, 53, 29, 15, 60}},
	{4, 6}: {
		{19, 13, 35, 7, 49},
		{42, 26, 38, 50, 22},
		{52, 21, 44, 28, 37},
		{25, 11, 14, 56, 41},
	},
	{5, 6}: {{3, 5, 33}, {6, 10, 34}, {12, 20, 36}, {9, 24, 40}, {48, 17, 18}},
}

// RSSRecover returns the balanced partition for the given active signer set.
// The result has length T; element j lists the subset bitmasks assigned to
// active[j]. Every subset of EnumerateSubsets(t,n) appears exactly once across
// the whole result, and each assigned subset contains its signer.
//
// active must be sorted, duplicate-free, in range, and of length exactly T.
func RSSRecover(active []int, t, n int) ([][]uint64, error) {
	if err := ValidateCommittee(t, n); err != nil {
		return nil, err
	}
	if len(active) != t {
		return nil, fmt.Errorf("rss: active set has %d signers, want T=%d", len(active), t)
	}
	prev := -1
	for _, id := range active {
		if id < 0 || id >= n {
			return nil, fmt.Errorf("rss: signer id %d out of range [0,%d)", id, n)
		}
		if id <= prev {
			return nil, fmt.Errorf("rss: active set must be sorted and duplicate-free, got %v", active)
		}
		prev = id
	}

	// Base case T == N: subset size M = 1, every subset is a singleton, so each
	// active signer takes exactly its own singleton {id} = bitmask 1<<id.
	if t == n {
		out := make([][]uint64, t)
		for j, id := range active {
			out[j] = []uint64{uint64(1) << uint(id)}
		}
		return out, nil
	}

	sharing, ok := canonicalSharing[[2]int{t, n}]
	if !ok {
		return nil, fmt.Errorf("rss: no balanced partition for (T=%d, N=%d)", t, n)
	}

	// Build the permutation φ: canonical index → actual party id. Active signers
	// fill canonical slots 0..T−1 in order; inactive parties fill T..N−1. This
	// translates the canonical bitmask tables to the actual active set.
	perm := make([]int, n)
	i1, i2 := 0, t
	activeSet := make(map[int]bool, t)
	for _, id := range active {
		activeSet[id] = true
	}
	for j := 0; j < n; j++ {
		if activeSet[j] {
			perm[i1] = j
			i1++
		} else {
			perm[i2] = j
			i2++
		}
	}

	out := make([][]uint64, t)
	for j, partyShares := range sharing {
		translated := make([]uint64, len(partyShares))
		for k, canonicalMask := range partyShares {
			var actual uint64
			for bit := 0; bit < n; bit++ {
				if canonicalMask&(uint64(1)<<uint(bit)) != 0 {
					actual |= uint64(1) << uint(perm[bit])
				}
			}
			translated[k] = actual
		}
		out[j] = translated
	}
	return out, nil
}
