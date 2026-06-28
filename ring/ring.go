// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ring is the single R_q = Z_q[X]/(X^n + 1) arithmetic substrate
// for the luxfi/dkg library. It adapts github.com/luxfi/lattice/v7/ring
// into a small, parameterized surface that both consumers bind onto:
//
//   - corona (Ringtail / Module-LWE): q = 0x1000000004A01 (48-bit), n = 256,
//     module shape K=8 rows × L=7 cols, Gaussian secret χ.
//   - pulsar (ML-DSA / FIPS-204):      q = 8380417 (23-bit),  n = 256,
//     module shape K=6 rows × L=5 cols, uniform-η secret χ.
//
// The DKG is GENERIC over a *Profile. A Profile is the ONE place a scheme's
// parameters live: ring, module shape (K, L), the secret-distribution sampler,
// the two public Pedersen matrices (A, B), and a KeyFinalize callback that
// maps the aggregated public commit T = Σ_i C_{i,0} ∈ R_q^K to the scheme's
// group public key (Ringtail β rounding vs ML-DSA t1 = HighBits). Nothing in
// vss/, blame/, transcript/ knows which scheme it is running — that is the
// decomplecting the library exists to achieve (DESIGN.md "one way, DRY,
// composable, orthogonal").
//
// Domain convention. Public matrices A, B and the Pedersen commits C_{i,k}
// are stored in NTT-Montgomery form (matching luxfi/lattice's MatrixVectorMul
// path and corona/dkg2's KAT-pinned layout). Secret shares f_i(j), g_i(j) and
// the aggregated secret share s_j are stored in STANDARD coefficient form.
// The aggregated commit T handed to KeyFinalize is in STANDARD coefficient
// form (INTT-reduced), because both finalizers (Ringtail rounding, ML-DSA
// Power2Round) operate coefficient-wise on the integer value.
package ring

import (
	"fmt"

	lring "github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Poly is one polynomial in R_q. Alias of the lattice type so consumers of
// luxfi/dkg never import lattice/v7/ring directly — the namespace qualifies
// the value (Hickey: "values, not places").
type Poly = lring.Poly

// Vector is a length-d vector of polynomials in R_q^d (a module element).
type Vector = structs.Vector[Poly]

// Matrix is a K×L matrix of polynomials in R_q^{K×L} (a public module map).
type Matrix = structs.Matrix[Poly]

// PRNG is the deterministic byte source samplers draw from. Alias of the
// lattice keyed-PRNG interface.
type PRNG = sampling.PRNG

// Ring wraps a single-modulus lattice ring at a fixed (n, q). All luxfi/dkg
// arithmetic flows through a *Ring; it is the lowest layer of the library.
type Ring struct {
	r    *lring.Ring
	logN int
	q    uint64
}

// New constructs a Ring for R_q = Z_q[X]/(X^{2^logN} + 1) with modulus q.
// q must be an NTT-friendly prime for ring degree 2^logN (q ≡ 1 mod 2^{logN+1}).
//
//	corona  : New(8, 0x1000000004A01)
//	ml-dsa  : New(8, 8380417)
func New(logN int, q uint64) (*Ring, error) {
	r, err := lring.NewRing(1<<logN, []uint64{q})
	if err != nil {
		return nil, fmt.Errorf("dkg/ring: New(logN=%d, q=%#x): %w", logN, q, err)
	}
	return &Ring{r: r, logN: logN, q: q}, nil
}

// Base returns the underlying lattice ring (for the scheme-specific profile
// bindings that need raw sampler construction). Not used by the generic DKG.
func (r *Ring) Base() *lring.Ring { return r.r }

// N returns the ring degree (number of coefficients per polynomial).
func (r *Ring) N() int { return r.r.N() }

// LogN returns log2 of the ring degree.
func (r *Ring) LogN() int { return r.logN }

// Q returns the prime modulus.
func (r *Ring) Q() uint64 { return r.q }

// NewPoly allocates a zero polynomial.
func (r *Ring) NewPoly() Poly { return r.r.NewPoly() }

// NewVec allocates a length-d zero vector in R_q^d.
func (r *Ring) NewVec(d int) Vector {
	v := make(Vector, d)
	for i := range v {
		v[i] = r.r.NewPoly()
	}
	return v
}

// --- single-polynomial operations (thin, value-stable pass-throughs) ---

// NTT maps p1 to the NTT domain, writing p2.
func (r *Ring) NTT(p1, p2 Poly) { r.r.NTT(p1, p2) }

// INTT maps p1 from the NTT domain back to coefficient form, writing p2.
func (r *Ring) INTT(p1, p2 Poly) { r.r.INTT(p1, p2) }

// MForm maps p1 into Montgomery form, writing p2.
func (r *Ring) MForm(p1, p2 Poly) { r.r.MForm(p1, p2) }

// IMForm maps p1 out of Montgomery form, writing p2.
func (r *Ring) IMForm(p1, p2 Poly) { r.r.IMForm(p1, p2) }

// Add sets p3 = p1 + p2 mod q.
func (r *Ring) Add(p1, p2, p3 Poly) { r.r.Add(p1, p2, p3) }

// Sub sets p3 = p1 - p2 mod q.
func (r *Ring) Sub(p1, p2, p3 Poly) { r.r.Sub(p1, p2, p3) }

// MulCoeffsMontgomeryThenAdd sets p3 += p1 ⊙ p2 (pointwise, NTT-Mont domain).
func (r *Ring) MulCoeffsMontgomeryThenAdd(p1, p2, p3 Poly) {
	r.r.MulCoeffsMontgomeryThenAdd(p1, p2, p3)
}

// MulCoeffsMontgomery sets p3 = p1 ⊙ p2 (pointwise, NTT-Mont domain).
func (r *Ring) MulCoeffsMontgomery(p1, p2, p3 Poly) {
	r.r.MulCoeffsMontgomery(p1, p2, p3)
}
