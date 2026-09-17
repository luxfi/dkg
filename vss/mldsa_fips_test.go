// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/luxfi/dkg/ring"
)

// mldsa_fips_test.go — the ML-DSA parameterization proofs (DESIGN.md hard
// invariant "Parameterization proven"):
//
//  1. RING FIDELITY: the generic lattice ring over the FIPS-204 modulus
//     q = 8380417 computes the negacyclic product A·s byte-identically to an
//     independent schoolbook convolution. This is the ground-truth proof that
//     the arithmetic the ML-DSA group key stands on is FIPS-204-faithful.
//  2. KeyFinalize ↔ FIPS-204 identity: the ML-DSA group key's Finalized vector
//     is exactly Power2Round(T) — t1 satisfies the FIPS-204 reconstruction
//     identity T = t1·2^13 + t0 and fits the 10-bit pk-packing width.
//  3. STOCK circl: a real cloudflare/circl ML-DSA-65 keygen→sign→verify round
//     trip proves the live FIPS-204 verifier the scheme targets, and the
//     profile parameters align with circl's.
//
// SCOPE NOTE (precise obstruction, honestly reported). A circl-BYTE-IDENTICAL
// public key for a specific rho — and a stock-circl-VERIFIABLE threshold
// signature from the no-reconstruct group key — are NOT foundation deliverables.
// They require (a) the pulsar consumer binding A = ExpandA(rho) over FIPS-204's
// own NTT (Phase 3) and (b) the TALUS threshold signer (Phase 2). The
// no-reconstruct group key T = A·s1 + B·u has a LARGE second component
// s2 = B·u (M-LWE-indistinguishable from a small χ_η sample but not itself
// small), so the standard FIPS-204 signing algorithm does not apply unchanged —
// TALUS's carry elimination is what produces a stock-verifiable signature. The
// v0.1 reconstruction path achieves trivial byte-equality precisely BECAUSE it
// reconstructs the seed, which the no-reconstruct invariant forbids. The
// foundation therefore proves FIPS-204 ring + key-map FIDELITY (below); the
// circl-verifiable signature is the signer's theorem (output-interchangeability,
// proofs/pulsar), consumed — not re-proved — here.

// schoolbookNegacyclic computes a·b in R_q = Z_q[X]/(X^n+1) by definition:
// c[k] = Σ_{i+j=k} a_i b_j − Σ_{i+j=k+n} a_i b_j (mod q). Ground truth,
// independent of any NTT.
func schoolbookNegacyclic(a, b []uint64, q uint64, n int) []uint64 {
	Q := new(big.Int).SetUint64(q)
	acc := make([]*big.Int, n)
	for i := range acc {
		acc[i] = new(big.Int)
	}
	for i := range n {
		ai := new(big.Int).SetUint64(a[i])
		for j := range n {
			prod := new(big.Int).Mul(ai, new(big.Int).SetUint64(b[j]))
			k := i + j
			if k < n {
				acc[k].Add(acc[k], prod)
			} else {
				acc[k-n].Sub(acc[k-n], prod) // X^n = -1
			}
		}
	}
	out := make([]uint64, n)
	for i := range n {
		acc[i].Mod(acc[i], Q) // Euclidean mod → [0,q)
		out[i] = acc[i].Uint64()
	}
	return out
}

// ringNegacyclic computes a·b via the lattice ring NTT path (the exact sequence
// the DKG uses for A·s), returning the coefficient-form product.
func ringNegacyclic(r *ring.Ring, a, b []uint64) []uint64 {
	pa := r.NewPoly()
	pb := r.NewPoly()
	copy(pa.Coeffs[0], a)
	copy(pb.Coeffs[0], b)
	// a → NTT-Mont (matches how A,B are stored); b → plain NTT (matches shares).
	// This is the exact sequence the DKG uses: MulCoeffsMontgomery cancels R,
	// and INTT alone (no IMForm) recovers the true coefficient-form product.
	r.NTT(pa, pa)
	r.MForm(pa, pa)
	r.NTT(pb, pb)
	prod := r.NewPoly()
	r.MulCoeffsMontgomery(pa, pb, prod) // Mont·plain → plain-NTT product
	r.INTT(prod, prod)                  // → true coefficient form
	return prod.Coeffs[0]
}

// TestMLDSA_RingFidelity_Schoolbook proves the lattice ring's negacyclic
// multiply equals the schoolbook convolution over the FIPS-204 modulus (and the
// Ringtail modulus), for random operands. This is the FIPS-204 ring-fidelity
// proof: the operation underlying A·s1 is correct vs ground truth.
func TestMLDSA_RingFidelity_Schoolbook(t *testing.T) {
	cases := []struct {
		name string
		q    uint64
		logN int
	}{
		{"mldsa-q", 8380417, 8},
		{"ringtail-q", 0x1000000004A01, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ring.New(tc.logN, tc.q)
			if err != nil {
				t.Fatal(err)
			}
			n := r.N()
			for iter := range 8 {
				a := randCoeffs(t, n, tc.q)
				b := randCoeffs(t, n, tc.q)
				want := schoolbookNegacyclic(a, b, tc.q, n)
				got := ringNegacyclic(r, a, b)
				for c := range n {
					if got[c] != want[c] {
						t.Fatalf("iter %d coeff %d: ring=%d schoolbook=%d (q=%#x)", iter, c, got[c], want[c], tc.q)
					}
				}
			}
		})
	}
}

// TestMLDSA_KeyFinalize_FIPSIdentity runs the DKG over the ML-DSA ring and
// proves the group key's Finalized vector is exactly FIPS-204 t1 of T: each
// coefficient satisfies T = t1·2^13 + t0 (t0 centered) and t1 fits 10 bits (the
// pk-packing width). This is the construction-level T↔FIPS-pk identity.
func TestMLDSA_KeyFinalize_FIPSIdentity(t *testing.T) {
	p, _ := ring.MLDSA65()
	ids, nodes := committee(t, 5)
	res, err := RunDKG(p, 5, 3, ids, nodes, [32]byte{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gk := res.GroupKey
	if gk.Aux == nil {
		t.Fatal("ML-DSA group key must carry t0 in Aux")
	}
	n := p.Ring.N()
	const d = 13
	for i := 0; i < p.K; i++ {
		for c := range n {
			T := int64(gk.T[i].Coeffs[0][c])
			t1 := int64(gk.Finalized[i].Coeffs[0][c])
			t0 := int64(gk.Aux[i].Coeffs[0][c]) - 8380417 // lift t0+q back to centered
			if t1 >= (1 << 10) {
				t.Fatalf("t1 coeff %d exceeds 10-bit pk width: %d", c, t1)
			}
			if t1<<d+t0 != T {
				t.Fatalf("FIPS-204 identity broken at [%d][%d]: t1·2^13+t0=%d, T=%d", i, c, t1<<d+t0, T)
			}
		}
	}
}

// TestMLDSA_StockCircl_Liveness proves the live stock FIPS-204 verifier the
// ML-DSA scheme targets, and that the profile parameters align with circl's.
func TestMLDSA_StockCircl_Liveness(t *testing.T) {
	// Stock keygen → sign → verify round-trip under cloudflare/circl.
	var seed [mldsa65.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pub, priv := mldsa65.NewKeyFromSeed(&seed)
	msg := []byte("foundation liveness check")
	ctx := []byte("lux-dkg")
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv, msg, ctx, false, sig); err != nil {
		t.Fatal(err)
	}
	if !mldsa65.Verify(pub, msg, ctx, sig) {
		t.Fatal("stock circl ML-DSA-65 verify failed — target verifier not live")
	}

	// Parameter alignment with the ML-DSA profile.
	p, _ := ring.MLDSA65()
	if p.Ring.Q() != 8380417 {
		t.Fatalf("profile q = %d, want FIPS-204 8380417", p.Ring.Q())
	}
	if p.Ring.N() != 256 {
		t.Fatalf("profile n = %d, want 256", p.Ring.N())
	}
	if p.K != 6 || p.L != 5 {
		t.Fatalf("profile shape %dx%d, want FIPS-204 ML-DSA-65 6x5", p.K, p.L)
	}
	if mldsa65.PublicKeySize != 1952 {
		t.Fatalf("circl pk size = %d, want 1952", mldsa65.PublicKeySize)
	}
}

// randCoeffs draws n uniform coefficients in [0,q).
func randCoeffs(t *testing.T, n int, q uint64) []uint64 {
	t.Helper()
	Q := new(big.Int).SetUint64(q)
	out := make([]uint64, n)
	for i := range n {
		v, err := rand.Int(rand.Reader, Q)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = v.Uint64()
	}
	return out
}
