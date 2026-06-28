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
// The number of RSS subsets C(N, N−T+1) grows combinatorially, and the local
// rejection-sampling acceptance rate decays with the committee, so Mithril is
// viable only for SMALL committees:
//
//	2 ≤ T ≤ N ≤ MaxParties   with   MaxParties = 6.
//
// This is sound for Pulsar because the Avalanche/Snow consensus carries the
// broad N>1000 economic security by repeated subsampling; the Pulsar signing
// committee only emits compact post-quantum EVIDENCE of an already-finalized
// digest (consensus quorum ≠ signing committee — see the Pulsar-M committee
// architecture). The maximum subset count over the admissible range is
// C(6,3) = 20 at (T=4, N=6).
package rss
