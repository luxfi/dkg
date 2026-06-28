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
		// No hardcoded reference entry (N > 6): compute the general Algorithm-6
		// balanced partition directly over the actual active set. The table is
		// kept only as a fast path and a cross-check oracle for N ≤ 6.
		return balancedPartition(active, t, n)
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

// balancedPartition is the GENERAL Algorithm-6 (ePrint 2026/013, RSSRecover)
// balanced partition for an arbitrary active signer set and any admissible
// (T, N) — including N beyond the hardcoded canonicalSharing table. It is the
// algorithmic generalisation that unblocks the fault-tolerant default committees
// n=8,t=7 and n=16,t=14 (and every other norm-viable T<N at N>6).
//
// Why a partition always exists. For an active set A (|A| = T) every M-subset S
// (M = N−T+1) intersects A in at least M + T − N = 1 party: S has M elements and
// the inactive set has only N − T = M − 1, so by pigeonhole S cannot fit inside
// the inactive parties and must contain ≥ 1 active signer. Each subset is
// therefore always assignable to some member of S ∩ A.
//
// Why max-flow (not greedy). A balanced partition minimises the MAXIMUM number
// of subsets any one signer is assigned — the per-signer work of a no-reconstruct
// aggregation. A least-loaded greedy is only a heuristic: on the owner default
// n=8,t=7 it lands max-load 6 against the optimum 4 (a 50% overload), because the
// eligibility constraint (a subset can only go to a member) makes naive greedy
// systematically pile load onto a few signers. We instead solve the exact problem
// — minimise max signer load subject to "each subset → one of its members" — as a
// degree-constrained bipartite assignment. The optimum L* is the least cap for
// which a feasible assignment exists; feasibility at a cap is a max-flow with
// source→subset (cap 1), subset→eligible-signer (cap 1), signer→sink (cap L).
// L is scanned upward from the information-theoretic floor ⌈C/T⌉ (L* equals that
// floor for every committee measured), so this is Algorithm 6's optimal partition,
// not an approximation.
//
// Determinism. The flow graph is built in a fixed layout (subsets in
// EnumerateSubsets order, signers in active order) and augmented by FIFO-BFS
// (Edmonds–Karp), so the partition is a pure function of (active, T, N): every
// honest signer and any auditor recompute the identical one — essential because a
// reconstruction or aggregation must sum each subset's short secret exactly once.
//
// Preconditions (guaranteed by RSSRecover, which validates before delegating;
// balancedPartition is unexported): active is sorted, duplicate-free, every id in
// [0, N), and len(active) == T. Returns a slice of length T; element j lists the
// subset bitmasks assigned to active[j], each of which contains active[j]. The
// union over all j is exactly EnumerateSubsets(t, n), each subset appearing once.
func balancedPartition(active []int, t, n int) ([][]uint64, error) {
	subsets := EnumerateSubsets(t, n)
	c := len(subsets)
	out := make([][]uint64, t)
	if c == 0 {
		return out, nil // no subsets (only for a non-admissible committee, rejected upstream)
	}
	slot := make(map[int]int, t) // party id → its index j in active
	for j, id := range active {
		slot[id] = j
	}
	// eligible[i] = the active-signer slots that may hold subset i (its members).
	eligible := make([][]int, c)
	for i, mask := range subsets {
		for _, id := range active { // active ascending → eligible slots ascending
			if mask&(uint64(1)<<uint(id)) != 0 {
				eligible[i] = append(eligible[i], slot[id])
			}
		}
		if len(eligible[i]) == 0 {
			// Unreachable for an admissible committee (pigeonhole); fail closed.
			return nil, fmt.Errorf("rss: subset 0b%b has no active member in %v", mask, active)
		}
	}
	// Scan the per-signer cap upward from the floor ⌈C/T⌉ to the first feasible L*.
	// Feasibility is monotone in L and is guaranteed by L = max subsets-per-signer
	// = SharesPerParty (the all-eligible assignment), so the scan always halts.
	floor := (c + t - 1) / t
	ceilCap := SharesPerParty(t, n)
	if ceilCap < floor {
		ceilCap = floor
	}
	for cap := floor; cap <= ceilCap; cap++ {
		if assign, ok := maxflowAssign(eligible, t, cap); ok {
			for i, mask := range subsets {
				j := assign[i]
				out[j] = append(out[j], mask)
			}
			return out, nil
		}
	}
	// Unreachable: feasibility holds by cap = SharesPerParty. Fail closed.
	return nil, fmt.Errorf("rss: no balanced partition found for (T=%d, N=%d) active=%v", t, n, active)
}

// maxflowAssign assigns every subset to exactly one eligible signer such that no
// signer receives more than capPerSigner subsets, or reports infeasibility at that
// cap. eligible[i] is the set of signer slots that may hold subset i. On success
// it returns assign with assign[i] = the signer slot holding subset i.
//
// It is a textbook Edmonds–Karp max-flow on the bipartite assignment network
// (source → subset, cap 1; subset → each eligible signer, cap 1; signer → sink,
// cap capPerSigner). Full flow C ⟺ a feasible assignment exists. The build order
// and BFS make the recovered assignment deterministic. Sizes are small (C ≤ 1336
// by the norm bound, T ≤ 62), so EK is comfortably fast.
func maxflowAssign(eligible [][]int, t, capPerSigner int) ([]int, bool) {
	c := len(eligible)
	const srcOffset = 1 // node 0 = source; subsets 1..c; signers c+1..c+t; sink last
	source := 0
	signer := func(j int) int { return c + 1 + j }
	sink := c + t + 1
	numNodes := c + t + 2

	// Edge list with paired forward/residual edges (forward at even index, its
	// residual at the XOR-1 odd index) for O(1) reverse lookup.
	type edge struct{ to, cap, flow int }
	edges := make([]edge, 0, 2*(c+c*t+t))
	adj := make([][]int, numNodes)
	addEdge := func(u, v, cp int) {
		adj[u] = append(adj[u], len(edges))
		edges = append(edges, edge{to: v, cap: cp})
		adj[v] = append(adj[v], len(edges))
		edges = append(edges, edge{to: u, cap: 0})
	}
	for i := 0; i < c; i++ {
		addEdge(source, srcOffset+i, 1)
		for _, j := range eligible[i] {
			addEdge(srcOffset+i, signer(j), 1)
		}
	}
	for j := 0; j < t; j++ {
		addEdge(signer(j), sink, capPerSigner)
	}

	flow := 0
	for {
		parentEdge := make([]int, numNodes)
		for i := range parentEdge {
			parentEdge[i] = -1
		}
		parentEdge[source] = -2
		queue := []int{source}
		for len(queue) > 0 && parentEdge[sink] == -1 {
			u := queue[0]
			queue = queue[1:]
			for _, ei := range adj[u] {
				e := edges[ei]
				if parentEdge[e.to] == -1 && e.cap-e.flow > 0 {
					parentEdge[e.to] = ei
					queue = append(queue, e.to)
				}
			}
		}
		if parentEdge[sink] == -1 {
			break // no augmenting path
		}
		// Augment by the bottleneck along the path (1 on the subset edges).
		bottleneck := int(^uint(0) >> 1)
		for v := sink; v != source; {
			ei := parentEdge[v]
			if r := edges[ei].cap - edges[ei].flow; r < bottleneck {
				bottleneck = r
			}
			v = edges[ei^1].to
		}
		for v := sink; v != source; {
			ei := parentEdge[v]
			edges[ei].flow += bottleneck
			edges[ei^1].flow -= bottleneck
			v = edges[ei^1].to
		}
		flow += bottleneck
	}
	if flow != c {
		return nil, false
	}
	// Recover: each subset's saturated forward edge points to its signer.
	assign := make([]int, c)
	for i := 0; i < c; i++ {
		assign[i] = -1
		for _, ei := range adj[srcOffset+i] {
			e := edges[ei]
			if e.to >= signer(0) && e.to <= signer(t-1) && e.cap == 1 && e.flow == 1 {
				assign[i] = e.to - signer(0)
				break
			}
		}
		if assign[i] == -1 {
			return nil, false // unreachable when flow == c
		}
	}
	return assign, true
}
