// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"crypto/subtle"
	"encoding/binary"

	lring "github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/zeebo/blake3"
)

// Module-element (Vector) and module-map (Matrix) algebra. Every routine here
// mirrors the corona/dkg2 + corona/utils domain convention byte-for-byte (the
// KAT-pinned Ringtail path), generalized to arbitrary (K, L, q). Porting the
// exact operation sequence — not re-deriving it — is what makes the generic
// ring identical to the proven corona arithmetic at the Ringtail parameters
// and well-defined at the ML-DSA parameters.
//
// Domain map (the one convention, used everywhere):
//   - public matrices A, B      : NTT-Montgomery form.
//   - secret coeff vectors c, r : standard coefficient form.
//   - commits C_k = A·NTT(c)+B·NTT(r) : plain-NTT form (Montgomery cancels
//     in MulCoeffsMontgomery(mont, plain) → plain).
//   - aggregated commit T (for KeyFinalize) : standard coefficient form, via
//     ConvertVecFromNTT(Σ_i C_{i,0}).

// NewVec allocates a length-d zero vector R_q^d.
func NewVec(r *Ring, d int) Vector { return r.NewVec(d) }

// CopyVec returns a deep copy of v.
func CopyVec(v Vector) Vector {
	out := make(Vector, len(v))
	for i := range v {
		out[i] = *v[i].CopyNew()
	}
	return out
}

// NTTVec maps each polynomial of v into the (plain) NTT domain in place.
// Used on a secret share f_i(j) before the public matrix multiply, matching
// dkg2.VerifyShareAgainstCommits.
func NTTVec(r *Ring, v Vector) {
	for i := range v {
		r.NTT(v[i], v[i])
	}
}

// ConvertVecToNTTMont maps each polynomial of v into NTT-Montgomery form in
// place (NTT then MForm). Used when a standard-form share must be folded into
// the NTT-Mont matrix path (e.g. β-noise contribution in path-(a) finalizers).
func ConvertVecToNTTMont(r *Ring, v Vector) {
	for i := range v {
		r.NTT(v[i], v[i])
		r.MForm(v[i], v[i])
	}
}

// ConvertVecFromNTT maps each polynomial of v out of the plain-NTT domain back
// to standard coefficient form in place (INTT). This materializes the aggregated
// public commit T = Σ_i C_{i,0} in TRUE integer coefficient form for
// KeyFinalize.
//
// CRITICAL — no IMForm. The commits are plain-NTT products N(A·c): a Montgomery
// matrix times a plain-NTT vector (MulCoeffsMontgomery) already cancels the R
// factor, so the product is the plain NTT of A·c, and INTT alone recovers A·c.
// An extra IMForm here would inject a spurious R^{-1}, scaling the group key by
// 1/R mod q — self-consistent under a same-scaled verifier (which is why a
// lattice-vs-lattice round-trip test misses it) but WRONG against ground truth.
// TestMLDSA_RingFidelity_Schoolbook pins this against an independent schoolbook
// convolution; the FIPS-204 t1 = HighBits(T) requires the TRUE A·s1+B·u.
func ConvertVecFromNTT(r *Ring, v Vector) {
	for i := range v {
		r.INTT(v[i], v[i])
	}
}

// VecAdd sets result = v1 + v2 element-wise mod q.
func VecAdd(r *Ring, v1, v2, result Vector) {
	for i := range v1 {
		r.Add(v1[i], v2[i], result[i])
	}
}

// VecSub sets result = v1 - v2 element-wise mod q.
func VecSub(r *Ring, v1, v2, result Vector) {
	for i := range v1 {
		r.Sub(v1[i], v2[i], result[i])
	}
}

// MatVecMul sets result = M · vec, where M is a K×L matrix in NTT-Montgomery
// form and vec is a length-L vector in (plain) NTT form. The result is a
// length-K vector in (plain) NTT form. result must be pre-zeroed and length K.
//
// This is the bare MulCoeffsMontgomeryThenAdd loop from corona/utils —
// Montgomery on one operand cancels, so a Mont matrix times a plain vector
// yields a plain product. Caller controls the NTT domain of vec.
func MatVecMul(r *Ring, M Matrix, vec, result Vector) {
	for i := range M {
		for j := range M[i] {
			r.MulCoeffsMontgomeryThenAdd(M[i][j], vec[j], result[i])
		}
	}
}

// ScalarMulVec sets result[i] = x · v[i] coefficient-wise mod q for every i.
// Works in any domain (coefficient or NTT) because scalar multiplication is
// applied per coefficient. Replaces corona's big.Int polyMulScalar /
// polyMulScalarNTT with the lattice ring's Barrett-reduced MulScalar (same
// canonical representative in [0,q), hence byte-identical result).
func ScalarMulVec(r *Ring, v Vector, x uint64, result Vector) {
	for i := range v {
		r.Base().MulScalar(v[i], x, result[i])
	}
}

// ConstantTimeVecEqual reports whether vectors a and b are equal, comparing
// every coefficient of every slot in constant time (no early exit on the first
// mismatched slot). Returns 1 iff equal, 0 otherwise.
//
// Constant-time over WHICH slot/coefficient differs — this is the corona
// response to RED-DKG-REVIEW Findings 5/6: a short-circuiting comparison leaks
// the location of a planted divergence to a timing observer. The Pedersen
// verification equation is public, but the comparison still runs CT so the
// verifier's timing reveals nothing beyond the single equal/not-equal bit.
func ConstantTimeVecEqual(a, b Vector) int {
	if len(a) != len(b) {
		return 0
	}
	eq := 1
	for i := range a {
		eq &= constantTimePolyEqual(a[i], b[i])
	}
	return eq
}

// constantTimePolyEqual returns 1 iff a == b coefficient-wise, in constant
// time over the coefficient values. Ported from corona/utils.
func constantTimePolyEqual(a, b Poly) int {
	if len(a.Coeffs) != len(b.Coeffs) {
		return 0
	}
	eq := 1
	for level := range a.Coeffs {
		al := a.Coeffs[level]
		bl := b.Coeffs[level]
		if len(al) != len(bl) {
			eq = 0
			continue
		}
		eq &= subtle.ConstantTimeCompare(uint64sToBytes(al), uint64sToBytes(bl))
	}
	return eq
}

// uint64sToBytes returns a little-endian byte view of a []uint64. The layout
// is byte-stable on every supported target (amd64, arm64).
func uint64sToBytes(s []uint64) []byte {
	out := make([]byte, 8*len(s))
	for i, v := range s {
		binary.LittleEndian.PutUint64(out[8*i:], v)
	}
	return out
}

// DeriveUniformMatrix builds a K×L matrix uniform over R_q in NTT-Montgomery
// form, deterministically from a nothing-up-my-sleeve seed. The seed is a
// domain-separation tag bound by the scheme profile (e.g. "corona.dkg2.A.v1").
// Every party derives byte-identical A, B from the public tag — there is no
// trusted setup of the public matrices.
//
// Derivation: BLAKE3(seed) → 32-byte key → lattice KeyedPRNG → UniformSampler,
// then sample K·L polynomials NTT-Mont. This matches corona/dkg2's
// derivePublicMatrix exactly (BLAKE3, not a transcript suite, so the matrix
// bytes are stable independent of any hash-suite rotation).
func DeriveUniformMatrix(r *Ring, K, L int, seed []byte) (Matrix, error) {
	h := blake3.New()
	if _, err := h.Write(seed); err != nil {
		return nil, err
	}
	key := h.Sum(nil)[:32]
	prng, err := sampling.NewKeyedPRNG(key)
	if err != nil {
		return nil, err
	}
	u := lring.NewUniformSampler(prng, r.r)
	m := make(Matrix, K)
	for i := range K {
		m[i] = make([]Poly, L)
		for j := range L {
			p := u.ReadNew()
			r.r.NTT(p, p)
			r.r.MForm(p, p)
			m[i][j] = p
		}
	}
	return m, nil
}

// SampleGaussianVec samples a length-d vector in standard coefficient form
// with each coefficient drawn from a discrete Gaussian D(sigma, bound),
// driven by prng. This is the corona/Ringtail secret distribution χ.
func SampleGaussianVec(r *Ring, d int, sigma, bound float64, prng PRNG) Vector {
	g := lring.NewGaussianSampler(prng, r.r, lring.DiscreteGaussian{Sigma: sigma, Bound: bound}, false)
	v := make(Vector, d)
	for i := range d {
		v[i] = g.ReadNew()
	}
	return v
}

// SampleBoundedUniformVec samples a length-d vector in standard coefficient
// form with each coefficient uniform in the centered range [-eta, eta] mod q
// (stored as the canonical representative in [0,q)). This is the ML-DSA secret
// distribution χ_η. Sampling is rejection-free over a [0, 2η] window expanded
// from prng bytes and recentered, giving exact uniformity on 2η+1 values.
func SampleBoundedUniformVec(r *Ring, d int, eta uint64, prng PRNG) Vector {
	n := r.N()
	q := r.Q()
	span := 2*eta + 1
	v := make(Vector, d)
	for i := range d {
		p := r.NewPoly()
		for c := range n {
			u := uniformBelow(prng, span)
			// centered value in [-eta, eta]; store as representative in [0,q).
			if u < eta {
				// negative: q - (eta - u)
				p.Coeffs[0][c] = q - (eta - u)
			} else {
				p.Coeffs[0][c] = u - eta
			}
		}
		v[i] = p
	}
	return v
}

// uniformBelow returns a uniformly random value in [0, bound) drawn from prng
// via rejection sampling on a byte-aligned window, avoiding modulo bias.
func uniformBelow(prng PRNG, bound uint64) uint64 {
	if bound <= 1 {
		return 0
	}
	// Smallest power-of-two byte width covering bound.
	var nbytes int
	max := bound
	for max > 0 {
		nbytes++
		max >>= 8
	}
	// Rejection threshold: largest multiple of bound that fits in 8*nbytes bits.
	limit := (^uint64(0)) >> (64 - 8*nbytes)
	limit = limit - (limit % bound)
	buf := make([]byte, nbytes)
	for {
		if _, err := prng.Read(buf); err != nil {
			// PRNG is a deterministic in-memory stream; a read error is a
			// programming fault, not a runtime condition. Fail loud.
			panic("dkg/ring: PRNG read failed: " + err.Error())
		}
		var x uint64
		for _, b := range buf {
			x = (x << 8) | uint64(b)
		}
		if x <= limit {
			return x % bound
		}
	}
}

// NewKeyedPRNG constructs a deterministic PRNG from a seed. Re-exported so
// scheme bindings and the DKG can derive byte-stable per-party randomness.
func NewKeyedPRNG(seed []byte) (PRNG, error) { return sampling.NewKeyedPRNG(seed) }
