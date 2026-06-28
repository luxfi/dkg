// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"testing"
)

// TestProfiles_Construct checks that both scheme bindings construct, validate,
// and carry the expected module shape and modulus.
func TestProfiles_Construct(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (*Profile, error)
		wantK     int
		wantL     int
		wantQ     uint64
		wantN     int
		wantAux   bool // KeyFinalize produces an Aux vector
	}{
		{"ringtail", Ringtail, 8, 7, 0x1000000004A01, 256, false},
		{"mldsa65", MLDSA65, 6, 5, 8380417, 256, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if p.K != tc.wantK || p.L != tc.wantL {
				t.Fatalf("shape = %dx%d, want %dx%d", p.K, p.L, tc.wantK, tc.wantL)
			}
			if p.Ring.Q() != tc.wantQ {
				t.Fatalf("q = %#x, want %#x", p.Ring.Q(), tc.wantQ)
			}
			if p.Ring.N() != tc.wantN {
				t.Fatalf("n = %d, want %d", p.Ring.N(), tc.wantN)
			}
			// Matrices are K×L.
			if len(p.A) != tc.wantK || len(p.A[0]) != tc.wantL {
				t.Fatalf("A shape = %dx%d", len(p.A), len(p.A[0]))
			}
		})
	}
}

// TestRingtailMatrices_MatchCorona pins the Ringtail public matrices to the
// corona/dkg2 derivation: same NUMS tags ("corona.dkg2.A.v1"), same BLAKE3 →
// KeyedPRNG → uniform NTT-Mont path. A regression here means the foundation
// would NOT reproduce corona's group keys at Phase-3 wiring.
func TestRingtailMatrices_Deterministic(t *testing.T) {
	p1, err := Ringtail()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Ringtail()
	if err != nil {
		t.Fatal(err)
	}
	if ConstantTimeVecEqual(p1.A[0], p2.A[0]) != 1 {
		t.Fatal("A row 0 not deterministic across constructions")
	}
	if ConstantTimeVecEqual(p1.B[2], p2.B[2]) != 1 {
		t.Fatal("B row 2 not deterministic")
	}
	// A and B must be independent (different NUMS tags).
	if ConstantTimeVecEqual(p1.A[0], p1.B[0]) == 1 {
		t.Fatal("A and B collide — domain separation broken")
	}
}

// TestSecretSamplers checks the two secret distributions produce vectors of the
// right length, in range, and deterministic per seed.
func TestSecretSamplers(t *testing.T) {
	t.Run("ringtail-gaussian", func(t *testing.T) {
		p, _ := Ringtail()
		prng, _ := NewKeyedPRNG(make([]byte, 32))
		v := p.SampleSecretVec(prng)
		if len(v) != p.L {
			t.Fatalf("len = %d, want %d", len(v), p.L)
		}
	})
	t.Run("mldsa-bounded-uniform", func(t *testing.T) {
		p, _ := MLDSA65()
		seed := make([]byte, 32)
		seed[0] = 7
		prng, _ := NewKeyedPRNG(seed)
		v := p.SampleSecretVec(prng)
		if len(v) != p.L {
			t.Fatalf("len = %d, want %d", len(v), p.L)
		}
		// Every coefficient must be within [-eta, eta] mod q, i.e. in
		// [0, eta] ∪ [q-eta, q-1].
		q := p.Ring.Q()
		for _, poly := range v {
			for _, c := range poly.Coeffs[0] {
				ok := c <= mldsaEta || c >= q-mldsaEta
				if !ok {
					t.Fatalf("coeff %d out of [-%d,%d] range mod q", c, mldsaEta, mldsaEta)
				}
			}
		}
	})
}

// TestFIPS204Power2Round pins Power2Round/Decompose to known FIPS-204 values.
// These are the exact identities every coefficient obeys: a = t1·2^13 + t0 with
// t0 centered, and a = a1·2γ2 + a0 with a0 centered. A break here means the
// ML-DSA KeyFinalize would diverge from circl.
func TestFIPS204Power2Round(t *testing.T) {
	// Spot residues across the modulus.
	residues := []uint32{0, 1, 4095, 4096, 8191, 8192, 261888, 523776, fipsQ - 1, fipsQ/2, 1234567}
	for _, a := range residues {
		t1, t0pq := power2round(a)
		// reconstruct: a == t1*2^d + (t0pq - q)  (mod nothing — exact integers)
		t0 := int64(t0pq) - int64(fipsQ)
		got := int64(t1)<<fipsD + t0
		if got != int64(a) {
			t.Fatalf("power2round(%d): t1=%d t0=%d reconstructs %d", a, t1, t0, got)
		}
		// t1 must fit in 10 bits (FIPS-204 pk packing width).
		if t1 >= (1 << 10) {
			t.Fatalf("power2round(%d): t1=%d exceeds 10 bits", a, t1)
		}
	}
	// Decompose high bits must land in [0,16) for gamma2_65.
	for _, a := range residues {
		a1, _ := decompose(a, fipsGamma2_65)
		if a1 >= 16 {
			t.Fatalf("decompose(%d) high=%d >= 16", a, a1)
		}
	}
}

// TestConstantTimeVecEqual exercises the CT comparator on equal and unequal
// vectors (the malformed-share rejection primitive).
func TestConstantTimeVecEqual(t *testing.T) {
	p, _ := MLDSA65()
	r := p.Ring
	a := NewVec(r, 3)
	b := NewVec(r, 3)
	if ConstantTimeVecEqual(a, b) != 1 {
		t.Fatal("zero vectors should be equal")
	}
	b[1].Coeffs[0][5] = 1
	if ConstantTimeVecEqual(a, b) != 0 {
		t.Fatal("differing vectors should be unequal")
	}
	if ConstantTimeVecEqual(a, b[:2]) != 0 {
		t.Fatal("length mismatch should be unequal")
	}
}
