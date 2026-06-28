// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mpc is the malicious-secure BGW multiparty-computation substrate of
// luxfi/dkg: Shamir secret sharing, secure multiplication, shared random bits,
// and the identifiable-abort hardening that the CarryCompare secure comparison
// (cscp/) composes from. It is GENERIC over the prime field GF(q) carried by a
// *ring.Profile — the Shamir field IS the scheme ring modulus, so a GF(q)
// reduction of a commitment coefficient equals its ring reduction (no
// cross-modulus correction). corona (q ≈ 2^48) and pulsar (q = 2^23 − 2^13 + 1)
// both bind onto the same substrate.
//
// ─────────────────────────────────────────────────────────────────────────────
// TWO LAYERS, ONE FILE-SET.
//
//  1. SEMI-HONEST substrate (field.go, shamir.go, bgw.go) — the proven BGW
//     primitives (Ben-Or–Goldwasser–Wigderson, STOC 1988): degree-reducing
//     secure multiplication and an XOR-folded shared-random-bit generator. These
//     enforce TALUS Theorem 10.1's N ≥ 2T−1 honest-majority barrier: the
//     degree-2(T−1) product of two degree-(T−1) sharings is only reconstructable
//     when N ≥ 2T−1 (MulShares refuses otherwise). Factored verbatim, in field
//     arithmetic, from the pulsar reference talus_mpc.go.
//
//  2. MALICIOUS hardening (committed.go, openshare.go, bitcheck.go,
//     blame_bridge.go) — identifiable abort (TALUS Phase B). A semi-honest BGW
//     trusts every party to (a) re-share consistently, (b) contribute genuine
//     {0,1} bits, and (c) open honestly. The hardening closes all three with
//     POST-QUANTUM-SOUND mechanisms only:
//
//     - committed re-shares (committed.go): every re-share carries a cSHAKE256
//     hash commitment (binding via collision resistance, full-range safe —
//     no shortness requirement, unlike a lattice commitment, and no DLog
//     group, unlike Feldman). The dealer's OWN committed N-share vector is
//     checked to be a degree-(T−1) Reed-Solomon codeword (CheckDegree) before
//     use; this is EXACT for any N ≥ T because it tests one party's own
//     committed data, not a mixed adversarial set. A degree fault is
//     publicly re-checkable evidence (ReshareFault → ReasonBadReshare).
//
//     - checked openings (openshare.go): a reconstruction is preceded by a
//     commit-then-open round — each party signs a commitment to its opening
//     share BEFORE any is revealed. A party whose revealed (share, nonce)
//     does not open its committed digest is named directly by the BINDING
//     (OpeningFault → ReasonBadOpening). Identification rests on commitment
//     binding, NOT Reed-Solomon error-correction: at N = 2T−1 a coalition of
//     T−1 can present a fake degree-(T−1) polynomial agreeing with 2(T−1) ≥ T
//     shares, out-voting the honest T, so RS decoding cannot identify the
//     honest value — it can only DETECT a non-codeword. Detection (CheckDegree
//     on the bound shares) flags an upstream-malformed committed re-share,
//     which then reduces to the committed.go degree fault.
//
//     - batched bit validity (bitcheck.go): each contributed random bit b is
//     proven b·(b−1)=0 by one committed secure multiplication; a Fiat-Shamir
//     random linear combination of the products (challenge bound to the bit
//     commitments) is opened ONCE and asserted zero (a single non-bit
//     survives with probability 1/q), with a per-party drill-down to
//     attribute (BitFault → ReasonBadBit).
//
//     Every detected deviation becomes a blame.Complaint (blame_bridge.go) the
//     SAME identifiable-abort machinery as a DKG bad-delivery adjudicates.
//
// The commitment, the signatures, and the Reed–Solomon structure are all
// post-quantum: cSHAKE256 (hash), ML-DSA-65 (lattice signature), and an
// information-theoretic linear code. No classical (discrete-log / pairing)
// assumption enters the substrate.
package mpc
