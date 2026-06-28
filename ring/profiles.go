// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import "fmt"

// profiles.go — the two concrete scheme bindings. These are the ONLY places
// the corona-vs-pulsar parameter differences are spelled out; everything above
// (vss/, blame/, transcript/) is generic over the *Profile they return.

// Ringtail parameters (corona / Module-LWE), matching corona/sign/config.go
// and corona/dkg2 exactly so the foundation reproduces the KAT-pinned corona
// arithmetic byte-for-byte at Phase-3 wiring time.
const (
	ringtailLogN   = 8
	ringtailQ      = 0x1000000004A01 // 48-bit NTT-friendly prime (sign.Q)
	ringtailK      = 8               // sign.M — commit rows
	ringtailL      = 7               // sign.N — secret cols
	ringtailSigmaE = 6.108187070284607
	ringtailXi     = 30      // rounding shift for bTilde
	ringtailQXi    = 0x40000 // post-rounding modulus (sign.QXi)
)

// Ringtail matrix domain-separation tags. Byte-identical to corona/dkg2 so the
// derived A, B match corona's public matrices exactly.
var (
	ringtailTagA = []byte("corona.dkg2.A.v1")
	ringtailTagB = []byte("corona.dkg2.B.v1")
)

// Ringtail returns the corona/Ringtail Module-LWE profile: K=8 × L=7 over the
// 48-bit prime, Gaussian secret χ = D(σ_E, 2σ_E), and KeyFinalize = round-to-Xi
// (the Ringtail β public key).
func Ringtail() (*Profile, error) {
	r, err := New(ringtailLogN, ringtailQ)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: Ringtail ring: %w", err)
	}
	a, err := DeriveUniformMatrix(r, ringtailK, ringtailL, ringtailTagA)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: Ringtail A: %w", err)
	}
	b, err := DeriveUniformMatrix(r, ringtailK, ringtailL, ringtailTagB)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: Ringtail B: %w", err)
	}
	bound := ringtailSigmaE * 2
	return &Profile{
		Name: "corona-ringtail-mlwe",
		Ring: r,
		K:    ringtailK,
		L:    ringtailL,
		A:    a,
		B:    b,
		SampleSecretVec: func(prng PRNG) Vector {
			return SampleGaussianVec(r, ringtailL, ringtailSigmaE, bound, prng)
		},
		KeyFinalize: ringtailFinalize,
	}, nil
}

// ringtailFinalize rounds each coefficient of T to bTilde = (T + 2^(Xi-1)) >> Xi,
// the corona Round_Xi map producing the Ringtail β public key. Verbatim
// corona/utils.RoundCoefficients.
func ringtailFinalize(p *Profile, T Vector) (*GroupPublicKey, error) {
	if len(T) != p.K {
		return nil, fmt.Errorf("dkg/ring: ringtailFinalize: T has %d rows, want %d", len(T), p.K)
	}
	n := p.Ring.N()
	bTilde := make(Vector, p.K)
	for i := range T {
		out := p.Ring.NewPoly()
		for c := 0; c < n; c++ {
			coeff := T[i].Coeffs[0][c]
			out.Coeffs[0][c] = (coeff + (1 << (ringtailXi - 1))) >> ringtailXi
		}
		bTilde[i] = out
	}
	return &GroupPublicKey{
		Scheme:    p.Name,
		T:         T,
		Finalized: bTilde,
		Aux:       nil,
	}, nil
}

// ML-DSA-65 parameters (pulsar / FIPS-204), matching pulsar/params.go ParamsP65.
const (
	mldsaLogN = 8
	mldsaQ    = 8380417 // FIPS-204 prime
	mldsaK    = 6       // FIPS-204 module dimension k — commit rows
	mldsaL    = 5       // FIPS-204 secret dimension ℓ — secret cols
	mldsaEta  = 4       // ML-DSA-65 secret coefficient bound η
)

// ML-DSA matrix domain-separation tags. The default A is a nothing-up-my-sleeve
// uniform matrix (self-consistent, FIPS-204-shaped). A pulsar consumer that
// needs byte-identity with a specific rho overrides A via Profile.WithMatrices,
// passing ExpandA(rho); the DKG is identical either way.
var (
	mldsaTagA = []byte("pulsar.dkg.A.v1")
	mldsaTagB = []byte("pulsar.dkg.B.v1")
)

// MLDSA65 returns the pulsar/ML-DSA-65 FIPS-204 profile: K=6 × L=5 over the
// 23-bit prime, uniform-η secret χ_η (η=4), and KeyFinalize = Power2Round (the
// FIPS-204 t1 public key). The aggregated commit T = A·s1 + B·u is the
// FIPS-204-shaped public-key inner vector; s2 = B·u is M-LWE-indistinguishable
// from a fresh χ_η sample (output-interchangeability, proofs/pulsar).
func MLDSA65() (*Profile, error) {
	r, err := New(mldsaLogN, mldsaQ)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: MLDSA65 ring: %w", err)
	}
	a, err := DeriveUniformMatrix(r, mldsaK, mldsaL, mldsaTagA)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: MLDSA65 A: %w", err)
	}
	b, err := DeriveUniformMatrix(r, mldsaK, mldsaL, mldsaTagB)
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: MLDSA65 B: %w", err)
	}
	return &Profile{
		Name: "pulsar-mldsa65-fips204",
		Ring: r,
		K:    mldsaK,
		L:    mldsaL,
		A:    a,
		B:    b,
		SampleSecretVec: func(prng PRNG) Vector {
			return SampleBoundedUniformVec(r, mldsaL, mldsaEta, prng)
		},
		KeyFinalize: mldsaFinalize,
	}, nil
}

// mldsaFinalize applies FIPS-204 Power2Round to T, yielding t1 (the public-key
// high-bits, in pk = (rho, t1)) and t0 (the low-bits the signer needs at hint
// time). Verbatim FIPS-204 §7.4.
func mldsaFinalize(p *Profile, T Vector) (*GroupPublicKey, error) {
	if len(T) != p.K {
		return nil, fmt.Errorf("dkg/ring: mldsaFinalize: T has %d rows, want %d", len(T), p.K)
	}
	t1, t0 := Power2RoundVec(p.Ring, T)
	return &GroupPublicKey{
		Scheme:    p.Name,
		T:         T,
		Finalized: t1,
		Aux:       t0,
	}, nil
}
