// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

// fips204.go — the FIPS 204 (ML-DSA) public-key rounding maps used by the
// ML-DSA profile's KeyFinalize. These are the verbatim FIPS 204 §7.4
// Power2Round and §7.4 Decompose/HighBits routines, byte-identical to
// cloudflare/circl's mldsa internal rounding (which the pulsar reference
// re-implements and KATs). They live here, in the foundation ring package,
// because mapping the aggregated public commit T to a FIPS-204-shaped group
// public key is a ring-level concern shared by any ML-DSA threshold consumer.
//
// Only the high-bits component is needed to form pk = (rho, t1); the low-bits
// t0 is returned alongside because every signer needs it at hint time
// (FIPS 204 Algorithm 7 line 3).

const (
	// fipsQ is the FIPS 204 prime modulus q = 2^23 - 2^13 + 1.
	fipsQ = 8380417
	// fipsD is the number of dropped low bits in Power2Round.
	fipsD = 13
	// fipsGamma2_65 = (q-1)/32 is the low-order rounding range for
	// ML-DSA-65 and ML-DSA-87 (a1 ∈ [0,16)).
	fipsGamma2_65 = 261888
	// fipsGamma2_44 = (q-1)/88 is the rounding range for ML-DSA-44
	// (a1 ∈ [0,44)).
	fipsGamma2_44 = 95232
)

// power2round splits 0 ≤ a < q into (t1, t0) with a = t1·2^d + t0 and
// -2^(d-1) < t0 ≤ 2^(d-1). Returns t1 and t0PlusQ (t0 lifted into [1,q) so it
// is a valid coefficient representative). Verbatim FIPS 204; matches circl.
func power2round(a uint32) (t1, t0PlusQ uint32) {
	a0 := a & ((1 << fipsD) - 1)
	a0 -= (1 << (fipsD - 1)) + 1
	a0 += uint32(int32(a0)>>31) & (1 << fipsD)
	a0 -= (1 << (fipsD - 1)) - 1
	t0PlusQ = fipsQ + a0
	t1 = (a - a0) >> fipsD
	return
}

// decompose splits 0 ≤ a < q into (a1, a0PlusQ) with a = a1·(2γ2) + a0 and the
// FIPS 204 boundary handling at q-1. gamma2 selects the parameter set. Returns
// a1 (the high bits, HighBits(a)) and a0PlusQ (low bits lifted into [1,q)).
// Verbatim FIPS 204 §7.4; matches circl byte-for-byte on all 8 380 417
// residues (the pulsar boundary KAT proves this).
func decompose(a uint32, gamma2 uint32) (a1, a0PlusQ uint32) {
	a1 = (a + 127) >> 7
	switch gamma2 {
	case fipsGamma2_65:
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 15
	case fipsGamma2_44:
		a1 = (a1*11275 + (1 << 23)) >> 24
		a1 ^= uint32(int32(43-a1)>>31) & a1
	default:
		return 0, 0
	}
	alpha := 2 * gamma2
	a0PlusQ = a - a1*alpha
	a0PlusQ += uint32(int32(a0PlusQ-(fipsQ-1)/2)>>31) & fipsQ
	return
}

// Power2RoundVec applies FIPS 204 Power2Round to every coefficient of every
// polynomial in T (standard coefficient form, coefficients in [0,q)), returning
// the high-bits vector t1 and the low-bits vector t0 (as representatives in
// [0,q)). This is the ML-DSA public-key derivation: pk = (rho, t1).
func Power2RoundVec(r *Ring, T Vector) (t1, t0 Vector) {
	t1 = make(Vector, len(T))
	t0 = make(Vector, len(T))
	n := r.N()
	for i := range T {
		p1 := r.NewPoly()
		p0 := r.NewPoly()
		for c := 0; c < n; c++ {
			h, l := power2round(uint32(T[i].Coeffs[0][c]))
			p1.Coeffs[0][c] = uint64(h)
			p0.Coeffs[0][c] = uint64(l)
		}
		t1[i], t0[i] = p1, p0
	}
	return
}

// HighBitsVec applies FIPS 204 HighBits (Decompose high part) to every
// coefficient of T at the given gamma2, returning the w1 vector. Exposed for
// the ML-DSA signer path and for KeyFinalize cross-checks.
func HighBitsVec(r *Ring, T Vector, gamma2 uint32) Vector {
	w1 := make(Vector, len(T))
	n := r.N()
	for i := range T {
		p := r.NewPoly()
		for c := 0; c < n; c++ {
			h, _ := decompose(uint32(T[i].Coeffs[0][c]), gamma2)
			p.Coeffs[0][c] = uint64(h)
		}
		w1[i] = p
	}
	return w1
}

// Power2Round is the scalar FIPS 204 Power2Round, exposed for tests and the
// schoolbook fidelity oracle.
func Power2Round(a uint32) (t1, t0PlusQ uint32) { return power2round(a) }

// Decompose is the scalar FIPS 204 Decompose, exposed for tests.
func Decompose(a, gamma2 uint32) (a1, a0PlusQ uint32) { return decompose(a, gamma2) }
