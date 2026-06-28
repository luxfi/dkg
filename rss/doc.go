// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package rss implements dealerless threshold ML-DSA key generation via
// Replicated Secret Sharing (RSS), following the Mithril construction of
// Celi, del Pino, Espitau, Niot and Prest (ePrint 2026/013, "Efficient
// Threshold ML-DSA from Short Secret Sharing", USENIX Security 2026).
//
// # The wall this routes around
//
// The luxfi/dkg/vss no-reconstruct Pedersen-VSS DKG produces a group key
// T = A·s1 + B·u in which the blinding s2 = B·u is LARGE (Module-LWE-
// indistinguishable from a small χ_η sample, but not actually short). Stock
// FIPS-204 is calibrated to ‖s2‖∞ ≤ η; with a large s2 the verifier's hint
// budget ω is blown and NO byte-stock-FIPS-204 signature exists. For ML-DSA
// the triple {no-reconstruct DKG, dealerless, byte-stock-FIPS-204-verifiable}
// is therefore pick-2 for the large-blinding construction.
//
// # How RSS beats it
//
// RSS keeps every share SHORT, so the reconstructed (s1, s2) stay genuinely
// small and the key is a real FIPS-204 key. For an (N, T) threshold define the
// subset size
//
//	M = N − T + 1
//
// and enumerate all M-subsets of {0,…,N−1}. There are
//
//	NumSubsets(N,T) = C(N, M) = C(N, N−T+1)
//
// of them. Each subset S carries a FRESH, INDEPENDENT short secret
// s^(S) ← χ_η (coefficients in [−η, η]); the composite secret is the plain SUM
//
//	s1 = Σ_S s1^(S),   s2 = Σ_S s2^(S)
//
// with NO Lagrange coefficients — reconstruction is pure addition, every
// reconstruction coefficient is 0 or 1. Hence
//
//	‖s2‖∞ ≤ C(N,M)·η  (small — at most 20·η for N≤6),
//
// versus ‖B·u‖∞ ≈ q/2 for the vss key. The small s2 keeps the hint within
// budget, so the produced key signs under an UNMODIFIED ML-DSA verifier. That
// is the wall, beaten.
//
// Party i holds every share whose subset contains i, i.e. C(N−1, M−1) subsets.
// No single party is in all C(N,M) subsets (whenever T ≥ 2), so no party ever
// learns the full secret: the scheme is dealerless by construction. Any T
// qualifying parties jointly cover all subsets (each replicated share is held
// by every member of its subset), so they can reconstruct via the balanced
// partition of partition.go — but no fewer than T can, because a coalition of
// ≤ T−1 parties is disjoint from at least one whole M-subset whose fresh short
// secret information-theoretically masks the key.
//
// # The exact (n, t) viability bound
//
// The reconstructed secret is the plain sum of C(N, N−T+1) fresh χ_η short
// secrets, so ‖s2‖∞ ≤ C(N,N−T+1)·η and the signer's hint term is bounded by
// ‖c·s2‖∞ ≤ τ·C(N,N−T+1)·η (the challenge c has τ ±1 coefficients). ML-DSA-65
// can find a hint — i.e. a byte-stock-FIPS-204 signature exists — only while
// that term stays inside ONE rounding bucket of width γ2 = (q−1)/32 = 261888.
// Hence the admission test (ValidateCommittee) is the per-(N,T) inequality
//
//	τ · C(N, N−T+1) · η  <  γ2 ,   with  τ=49, η=4, γ2=261888  (ML-DSA-65).
//
// This is NOT a flat N cap; it admits or rejects each (N,T) on its own merits.
// Worked numbers: n=8,t=7 → τCη=5 488 (48× under γ2, viable); n=8,t=8 → 1 568;
// n=16,t=14 → 109 760 (2.4× under γ2, tight but viable); n=16,t=12 → 856 128
// (> γ2 — hint budget blown, correctly rejected). The closer τCη is to γ2 the
// more signing attempts the r0 = w0 − c·s2 rejection costs — a benchmark
// concern, not a hard reject (see HintBudgetUsage).
//
// This is sound for Pulsar because the Avalanche/Snow consensus carries the
// broad N>1000 economic security by repeated subsampling; a Pulsar signing
// committee only emits compact post-quantum EVIDENCE of an already-finalized
// digest, and the sampled-certificate layer accumulates PQ confidence over r
// independent committees (Pr[capture]^r), so each committee can stay small
// (consensus quorum ≠ signing committee — see the Pulsar sampled-cert
// architecture).
package rss
