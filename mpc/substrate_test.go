// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/ring"
)

// evalPoints returns the canonical 1..n eval points for an n-party committee.
func evalPoints(n int) []Elem {
	pts := make([]Elem, n)
	for i := range pts {
		pts[i] = Elem(i + 1)
	}
	return pts
}

func mldsaField(t *testing.T) *Field {
	t.Helper()
	f, err := NewField(8380417)
	if err != nil {
		t.Fatalf("NewField: %v", err)
	}
	return f
}

func TestField_Arithmetic(t *testing.T) {
	f := mldsaField(t)
	q := f.Q()
	// Add/Sub/Neg wraparound.
	if got := f.Add(q-1, 5); got != 4 {
		t.Fatalf("Add wrap: got %d want 4", got)
	}
	if got := f.Sub(3, 10); got != q-7 {
		t.Fatalf("Sub wrap: got %d want %d", got, q-7)
	}
	if got := f.Add(f.Neg(12345), 12345); got != 0 {
		t.Fatalf("Neg: got %d want 0", got)
	}
	// Mul + Inv round-trip on a sweep.
	for _, a := range []Elem{1, 2, 3, 100, q - 1, 4194303, 8000000} {
		inv := f.Inv(a)
		if got := f.Mul(a, inv); got != 1 {
			t.Fatalf("Mul/Inv: a=%d a·a^-1=%d want 1", a, got)
		}
	}
	if f.BitLen() != 23 {
		t.Fatalf("BitLen: got %d want 23", f.BitLen())
	}
}

func TestField_FromProfile(t *testing.T) {
	mldsa, err := ring.MLDSA65()
	if err != nil {
		t.Fatalf("ring.MLDSA65(): %v", err)
	}
	ringtail, err := ring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail(): %v", err)
	}
	for _, p := range []*ring.Profile{mldsa, ringtail} {
		f, err := FieldFromProfile(p)
		if err != nil {
			t.Fatalf("FieldFromProfile(%s): %v", p.Name, err)
		}
		if f.Q() != p.Ring.Q() {
			t.Fatalf("%s: field q=%d ring q=%d", p.Name, f.Q(), p.Ring.Q())
		}
		// Mul/Inv must round-trip at the (possibly 48-bit) modulus too.
		a := Elem(123456789) % f.Q()
		if got := f.Mul(a, f.Inv(a)); got != 1 {
			t.Fatalf("%s: Mul/Inv got %d want 1", p.Name, got)
		}
	}
}

func TestShamir_ShareReconstruct(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	secret := Elem(987654)
	shares, err := f.ShareScalar(secret, pts, th, rand.Reader)
	if err != nil {
		t.Fatalf("ShareScalar: %v", err)
	}
	// Any t shares reconstruct; fewer than t do not (with overwhelming prob).
	got, err := f.Reconstruct(pts[:th], shares[:th])
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if got != secret {
		t.Fatalf("Reconstruct: got %d want %d", got, secret)
	}
	// A different t-subset reconstructs the same secret.
	idx := []int{1, 3, 4}
	got2, err := f.InterpolateAtZeroSubset(pts, shares, idx)
	if err != nil {
		t.Fatalf("InterpolateAtZeroSubset: %v", err)
	}
	if got2 != secret {
		t.Fatalf("subset reconstruct: got %d want %d", got2, secret)
	}
}

func TestBGW_SecureMultiply(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3 // n >= 2t-1 = 5
	pts := evalPoints(n)
	x, y := Elem(111111), Elem(222222)
	xs, err := f.ShareScalar(x, pts, th, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ys, err := f.ShareScalar(y, pts, th, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	zs, err := f.MulShares(xs, ys, pts, th, rand.Reader)
	if err != nil {
		t.Fatalf("MulShares: %v", err)
	}
	// The product sharing is fresh degree-(t-1): any t shares reconstruct x·y.
	want := f.Mul(x, y)
	for _, idx := range [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}} {
		got, err := f.InterpolateAtZeroSubset(pts, zs, idx)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("MulShares subset %v: got %d want %d", idx, got, want)
		}
	}
}

func TestBGW_RefusesBelowBarrier(t *testing.T) {
	f := mldsaField(t)
	const n, th = 4, 3 // n=4 < 2t-1=5
	pts := evalPoints(n)
	xs, _ := f.ShareScalar(1, pts, th, rand.Reader)
	ys, _ := f.ShareScalar(1, pts, th, rand.Reader)
	if _, err := f.MulShares(xs, ys, pts, th, rand.Reader); err != ErrNotEnoughParties {
		t.Fatalf("MulShares below barrier: got %v want ErrNotEnoughParties", err)
	}
}

func TestBGW_SharedRandomBit(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	for _, bits := range [][]bool{
		{false, false, false, false, false}, // XOR = 0
		{true, false, false, false, false},  // XOR = 1
		{true, true, false, false, false},   // XOR = 0
		{true, true, true, false, false},    // XOR = 1
	} {
		sh, err := f.SharedRandomBit(pts, th, bits, rand.Reader)
		if err != nil {
			t.Fatalf("SharedRandomBit: %v", err)
		}
		want := Elem(0)
		for _, b := range bits {
			if b {
				want ^= 1
			}
		}
		got, err := f.Reconstruct(pts[:th], sh[:th])
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("SharedRandomBit %v: got %d want %d", bits, got, want)
		}
	}
}
