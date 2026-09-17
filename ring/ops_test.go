// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"testing"
)

// TestMultiplyRoundTrip checks the documented domain convention: a NTT-Mont
// matrix times a plain-NTT vector, INTT'd, recovers the true product. The
// identity multiply (A = identity-ish) and the scalar cases anchor it.
func TestRingOps_AddSubScalar(t *testing.T) {
	r, err := New(8, 8380417)
	if err != nil {
		t.Fatal(err)
	}
	a := NewVec(r, 2)
	b := NewVec(r, 2)
	a[0].Coeffs[0][0] = 10
	a[1].Coeffs[0][3] = 5
	b[0].Coeffs[0][0] = 7
	b[1].Coeffs[0][3] = 1

	sum := NewVec(r, 2)
	VecAdd(r, a, b, sum)
	if sum[0].Coeffs[0][0] != 17 || sum[1].Coeffs[0][3] != 6 {
		t.Fatalf("VecAdd wrong: %d %d", sum[0].Coeffs[0][0], sum[1].Coeffs[0][3])
	}
	diff := NewVec(r, 2)
	VecSub(r, a, b, diff)
	if diff[0].Coeffs[0][0] != 3 || diff[1].Coeffs[0][3] != 4 {
		t.Fatalf("VecSub wrong: %d %d", diff[0].Coeffs[0][0], diff[1].Coeffs[0][3])
	}
	scaled := NewVec(r, 2)
	ScalarMulVec(r, a, 3, scaled)
	if scaled[0].Coeffs[0][0] != 30 || scaled[1].Coeffs[0][3] != 15 {
		t.Fatalf("ScalarMulVec wrong: %d %d", scaled[0].Coeffs[0][0], scaled[1].Coeffs[0][3])
	}
}

// TestMatVecMul_Schoolbook checks K×L matrix-vector multiply over R_q matches a
// per-entry schoolbook negacyclic sum, validating the MatVecMul + NTT path that
// the DKG commit/verify uses.
func TestMatVecMul_Schoolbook(t *testing.T) {
	r, _ := New(8, 8380417)
	n := r.N()
	K, L := 3, 2
	// Random standard-form matrix Acoef and vector vcoef.
	prng, _ := NewKeyedPRNG(make([]byte, 32))
	Acoef := make([][]Vector, 0) // unused; build directly
	_ = Acoef
	// Build A in NTT-Mont from random standard polys; keep the standard copies.
	A := make(Matrix, K)
	Astd := make([][]Poly, K)
	for i := range K {
		A[i] = make([]Poly, L)
		Astd[i] = make([]Poly, L)
		for j := range L {
			p := r.NewPoly()
			fillPseudo(p, n, uint64(i*7+j*13+1))
			Astd[i][j] = *p.CopyNew()
			r.NTT(p, p)
			r.MForm(p, p)
			A[i][j] = p
		}
	}
	v := NewVec(r, L)
	vstd := make([]Poly, L)
	for j := range L {
		fillPseudo(v[j], n, uint64(j*101+5))
		vstd[j] = *v[j].CopyNew()
	}
	_ = prng

	// Ring path: NTT v (plain), MatVecMul, INTT.
	vN := CopyVec(v)
	NTTVec(r, vN)
	got := NewVec(r, K)
	MatVecMul(r, A, vN, got)
	ConvertVecFromNTT(r, got)

	// Schoolbook: result[i] = Σ_j Astd[i][j] * vstd[j] (negacyclic).
	for i := range K {
		want := make([]uint64, n)
		for j := range L {
			pc := negacyclicMul(Astd[i][j].Coeffs[0], vstd[j].Coeffs[0], r.Q(), n)
			for c := range n {
				want[c] = (want[c] + pc[c]) % r.Q()
			}
		}
		for c := range n {
			if got[i].Coeffs[0][c] != want[c] {
				t.Fatalf("row %d coeff %d: got %d want %d", i, c, got[i].Coeffs[0][c], want[c])
			}
		}
	}
}

// TestDeriveUniformMatrix_Shape checks derivation produces a K×L NTT-Mont
// matrix and is seed-deterministic + domain-separated.
func TestDeriveUniformMatrix_Shape(t *testing.T) {
	r, _ := New(8, 8380417)
	m1, err := DeriveUniformMatrix(r, 6, 5, []byte("tag-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != 6 || len(m1[0]) != 5 {
		t.Fatalf("shape %dx%d", len(m1), len(m1[0]))
	}
	m1b, _ := DeriveUniformMatrix(r, 6, 5, []byte("tag-1"))
	if ConstantTimeVecEqual(m1[0], m1b[0]) != 1 {
		t.Fatal("derivation not deterministic")
	}
	m2, _ := DeriveUniformMatrix(r, 6, 5, []byte("tag-2"))
	if ConstantTimeVecEqual(m1[0], m2[0]) == 1 {
		t.Fatal("different tags collided")
	}
}

// TestGroupKeyEncode checks the public-key encoding is deterministic and
// scheme/finalized-sensitive.
func TestGroupKeyEncode(t *testing.T) {
	r, _ := New(8, 8380417)
	v := NewVec(r, 2)
	v[0].Coeffs[0][0] = 42
	g := &GroupPublicKey{Scheme: "s", Finalized: v}
	e1 := g.Encode()
	e2 := g.Encode()
	if string(e1) != string(e2) {
		t.Fatal("encode not deterministic")
	}
	v[0].Coeffs[0][0] = 43
	if string(g.Encode()) == string(e1) {
		t.Fatal("encode insensitive to finalized change")
	}
}

// TestProfileWithMatrices checks the ML-DSA ExpandA override seam.
func TestProfileWithMatrices(t *testing.T) {
	p, _ := MLDSA65()
	custom, _ := DeriveUniformMatrix(p.Ring, p.K, p.L, []byte("expandA-rho"))
	p2 := p.WithMatrices(custom, p.B)
	if ConstantTimeVecEqual(p2.A[0], custom[0]) != 1 {
		t.Fatal("WithMatrices did not replace A")
	}
	if ConstantTimeVecEqual(p.A[0], custom[0]) == 1 {
		t.Fatal("WithMatrices mutated the original profile")
	}
	if err := p2.Validate(); err != nil {
		t.Fatalf("overridden profile invalid: %v", err)
	}
}

// TestHighBitsVec exercises the HighBits path used by the signer.
func TestHighBitsVec(t *testing.T) {
	r, _ := New(8, 8380417)
	T := NewVec(r, 1)
	T[0].Coeffs[0][0] = 523776 // = 2*gamma2 for ml-dsa-65 → high bit 1
	w1 := HighBitsVec(r, T, 261888)
	if w1[0].Coeffs[0][0] != 1 {
		t.Fatalf("HighBits(2γ2) = %d, want 1", w1[0].Coeffs[0][0])
	}
}

// --- test helpers ---

// fillPseudo fills p with a deterministic pseudo-random-ish pattern mod q.
func fillPseudo(p Poly, n int, seed uint64) {
	x := seed | 1
	for c := range n {
		x = x*6364136223846793005 + 1442695040888963407
		p.Coeffs[0][c] = x % 8380417
	}
}

// negacyclicMul is the schoolbook product in Z_q[X]/(X^n+1).
func negacyclicMul(a, b []uint64, q uint64, n int) []uint64 {
	c := make([]uint64, n)
	for i := range n {
		for j := range n {
			prod := (a[i] % q) * (b[j] % q) % q
			k := i + j
			if k < n {
				c[k] = (c[k] + prod) % q
			} else {
				c[k-n] = (c[k-n] + q - prod) % q
			}
		}
	}
	return c
}
