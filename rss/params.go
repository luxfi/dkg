// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rss

import "fmt"

// ML-DSA-65 boundary-clearance constants (FIPS 204 §4 / §7.4). These are the
// parameters that decide whether an RSS committee's reconstructed secret stays
// short enough to admit a byte-stock-FIPS-204 signature.
//
//   - mldsaTau   = 49      number of ±1 coefficients in the challenge c.
//   - mldsaEta   = 4       χ_η coefficient bound of every per-subset short secret
//     (= ring.Profile.Eta for MLDSA65).
//   - mldsaGamma2= 261888  (q−1)/32, the low-order rounding range. It is the
//     width of one HighBits bucket and therefore the
//     boundary-clearance margin the signer's r0 = w0 − c·s2
//     term must fit inside for a hint to exist at all.
const (
	mldsaTau    = 49
	mldsaEta    = 4
	mldsaGamma2 = 261888
)

// MaxBitmaskParties is the hard representation ceiling on N: subsets are encoded
// as uint64 bitmasks (bit i ⇔ party i ∈ subset), so N must fit in 63 usable
// bits. This is NOT the admission cap — the real constraint is the per-(N,T)
// norm bound in ValidateCommittee, which rejects almost every committee far
// below 63. It is only the bound past which the encoding itself breaks.
const MaxBitmaskParties = 63

// maxViableSubsets = ⌊γ2 / (τ·η)⌋ is the largest replicated-subset count
// C(N, N−T+1) that can clear the boundary margin: τ·C·η < γ2 ⟺ C < γ2/(τη).
// It is used purely as an overflow guard so ValidateCommittee can compute the
// norm bound in fixed-width arithmetic; the admission decision is stated as the
// explicit τ·C·η < γ2 inequality below.
const maxViableSubsets = mldsaGamma2 / (mldsaTau * mldsaEta) // = 1336

// MaxParties is the CONSERVATIVE cap below which EVERY (2 ≤ T ≤ N) committee is
// both norm-viable AND cheap to rejection-sample (signing stays ≲100 attempts).
// It is NOT the admission gate — the real per-(N,T) gate is ValidateCommittee,
// which admits larger HIGH-threshold committees (e.g. the owner default n=8,t=7
// with C(8,2)=28, and n=16,t=14 with C(16,3)=560 — both ≪ maxViableSubsets) while
// rejecting low-threshold large-N committees (n=16,t=12, n=64,t=5) whose subset
// norm blows the FIPS-204 hint budget. Exhaustive tests + conservative policy
// defaults iterate to MaxParties; the sampled-committee families (n=8,t=7,m=12,r=8)
// admit via ValidateCommittee directly. See lux_pulsar_sampled_cert.
const MaxParties = 6

// ErrCommittee is returned for any (T, N) the RSS construction cannot admit. It
// is fail-closed: an out-of-range or norm-blown committee never silently
// degrades to a weaker mode. Reason distinguishes the two failure causes so a
// caller (or a benchmark harness) can tell a structural reject from a hint-budget
// reject.
type ErrCommittee struct {
	T, N         int
	Used, Margin uint64 // worst-case ‖c·s2‖∞ = τ·C·η, and the γ2 it must clear (0 for a structural reject)
	Reason       string
}

func (e *ErrCommittee) Error() string {
	if e.Margin == 0 {
		return fmt.Sprintf("rss: committee (T=%d, N=%d) structurally invalid: %s "+
			"(require 2 ≤ T ≤ N ≤ %d)", e.T, e.N, e.Reason, MaxBitmaskParties)
	}
	return fmt.Sprintf("rss: committee (T=%d, N=%d) blows the FIPS-204 hint budget: "+
		"worst-case ‖c·s2‖∞ = τ·C(N,N−T+1)·η = %d ≥ γ2 = %d — no byte-stock-FIPS-204 "+
		"signature can exist for this committee", e.T, e.N, e.Used, e.Margin)
}

// HintBudgetUsage returns the two numbers the viability decision turns on:
//
//	used   = τ · C(N, N−T+1) · η   the worst-case ‖c·s2‖∞ of the reconstructed
//	                               RSS secret (c has τ ±1's; ‖s2‖∞ ≤ C·η).
//	margin = γ2                    the FIPS-204 boundary-clearance width it must
//	                               stay strictly under.
//
// A committee is viable iff used < margin. The ratio used/margin is the
// rejection-sampling tightness: the closer to 1, the more signing attempts the
// r0 = w0 − c·s2 rejection costs — a benchmark concern, NOT an admission gate
// (the owner explicitly benchmarks the tight sets). For a committee whose
// subset count is so large that τ·C·η would overflow uint64, used is returned as
// the uint64 maximum ("effectively infinite, certainly ≥ γ2") so the comparison
// still rejects it.
func HintBudgetUsage(t, n int) (used, margin uint64) {
	c := NumSubsets(t, n)
	if c <= 0 {
		return ^uint64(0), mldsaGamma2 // degenerate / Binomial overflow → over budget
	}
	// τ·C·η in fixed-width arithmetic. C can reach C(63,31) ≈ 9.16e17, so guard
	// the multiply: any C past safeC would overflow uint64 and is certainly over
	// budget (it dwarfs γ2). Below safeC the true value is returned for reporting.
	const safeC = (^uint64(0)) / (mldsaTau * mldsaEta)
	if uint64(c) > safeC {
		return ^uint64(0), mldsaGamma2
	}
	return uint64(c) * (mldsaTau * mldsaEta), mldsaGamma2
}

// ValidateCommittee enforces the exact per-(N,T) Mithril viability bound. This
// is the one place the committee constraint is checked; every entry point routes
// through it so the bound cannot be bypassed. Fail-closed.
//
// A committee (T, N) is admitted iff BOTH hold:
//
//  1. structural:  2 ≤ T ≤ N ≤ MaxBitmaskParties  (a real threshold that fits
//     the uint64 subset encoding);
//  2. norm budget: τ · C(N, N−T+1) · η  <  γ2 .
//
// (2) is the load-bearing condition. The RSS secret reconstructs as the plain
// sum of C(N, N−T+1) fresh χ_η short secrets, so ‖s2‖∞ ≤ C·η and the signer's
// hint term ‖c·s2‖∞ ≤ τ·C·η. ML-DSA-65 certifies HighBits stability (a hint can
// be found) only while that term stays inside one rounding bucket of width γ2.
// Beyond γ2 the hint budget is structurally blown and NO byte-stock-FIPS-204
// signature exists for the committee — exactly the pick-2 wall, now as a clean
// per-(N,T) inequality rather than a flat N cap.
//
// Admitted (worked numerically): n=8,t=7 (τCη=5 488, 48× margin) · n=8,t=8
// (1 568) · n=16,t=14 (109 760, 2.4× margin — tight but viable). Rejected:
// n=16,t=12 (856 128 > γ2, hint budget blown).
func ValidateCommittee(t, n int) error {
	if t < 2 {
		return &ErrCommittee{T: t, N: n, Reason: "T must be ≥ 2 (a real threshold)"}
	}
	if t > n {
		return &ErrCommittee{T: t, N: n, Reason: "T must not exceed N"}
	}
	if n > MaxBitmaskParties {
		return &ErrCommittee{T: t, N: n, Reason: "N exceeds the uint64 subset-bitmask ceiling"}
	}
	used, margin := HintBudgetUsage(t, n)
	if used >= margin {
		return &ErrCommittee{T: t, N: n, Used: used, Margin: margin}
	}
	// ValidateCommittee is the NORM-viability gate only (is this committee in the
	// stock-FIPS-204-signable norm regime?). SIGNABILITY also needs the
	// reconstruction partition (Algorithm 6): the T==N base case is algorithmic,
	// and T<N needs a canonicalSharing entry (table-limited to N≤6 until the
	// general partition lands). A norm-viable-but-no-partition committee (e.g. the
	// owner default n=8,t=7) keygens fine but Sign fails CLOSED with "no balanced
	// partition" — not a fail-open bug, a clearly-erroring known gap. Partition
	// availability is checked at sign time, not here.
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
	if t < 2 || t > n || n > MaxBitmaskParties {
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
	for i := range n {
		if mask&(uint64(1)<<uint(i)) != 0 {
			members = append(members, i)
		}
	}
	return members
}
