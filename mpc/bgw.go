// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import "io"

// bgw.go — the semi-honest honest-majority BGW substrate (Ben-Or–Goldwasser–
// Wigderson, STOC 1988), factored from the pulsar reference talus_mpc.go into
// field arithmetic. Secure multiplication degree-reduces the product of two
// degree-(T-1) sharings back to degree T-1; the XOR-folded shared-random-bit
// generator exercises that gate exactly as the CSCP carry circuit does.
//
// These primitives are SOUND for a semi-honest adversary. The malicious-secure
// variant — committed re-shares with verified openings — lives in committed.go
// and CALLS the same degree-reduction recombination, so the arithmetic is shared
// (DRY) and only the verification wraps it.

// AddShares is the free, local, degree-preserving share addition.
func (f *Field) AddShares(x, y []Elem) ([]Elem, error) {
	if len(x) != len(y) {
		return nil, ErrShape
	}
	out := make([]Elem, len(x))
	for i := range x {
		out[i] = f.Add(x[i], y[i])
	}
	return out, nil
}

// SubShares is local degree-preserving share subtraction (x - y).
func (f *Field) SubShares(x, y []Elem) ([]Elem, error) {
	if len(x) != len(y) {
		return nil, ErrShape
	}
	out := make([]Elem, len(x))
	for i := range x {
		out[i] = f.Sub(x[i], y[i])
	}
	return out, nil
}

// ScalarMulShares multiplies a sharing by a PUBLIC scalar (local, free).
func (f *Field) ScalarMulShares(scalar Elem, x []Elem) []Elem {
	out := make([]Elem, len(x))
	for i := range x {
		out[i] = f.Mul(scalar, x[i])
	}
	return out
}

// reduceWeights returns the degree-2(T-1) Lagrange-at-0 weights r_i over ALL N
// evaluation points. These recombine the per-party re-shares so that Σ_i r_i·p_i
// = X·Y, degree-reducing the product back to a fresh degree-(T-1) sharing. Shared
// by the semi-honest MulShares and the malicious CommittedMul.
func (f *Field) reduceWeights(evalPoints []Elem) []Elem {
	r := make([]Elem, len(evalPoints))
	for i := range evalPoints {
		r[i] = f.LagrangeAtZero(evalPoints[i], evalPoints)
	}
	return r
}

// recombineReshares applies the degree-2(T-1) recombination: given each party
// i's degree-(T-1) re-share row reshares[i] (its sharing of the local product
// p_i) and the public weights r, returns zShares[k] = Σ_i r_i·reshares[i][k], a
// fresh degree-(T-1) sharing of X·Y.
func (f *Field) recombineReshares(reshares [][]Elem, r []Elem, n int) []Elem {
	z := make([]Elem, n)
	for k := 0; k < n; k++ {
		var acc Elem
		for i := 0; i < n; i++ {
			acc = f.Add(acc, f.Mul(r[i], reshares[i][k]))
		}
		z[k] = acc
	}
	return z
}

// MulShares performs one SEMI-HONEST BGW secure multiplication: given degree-
// (T-1) sharings of X and Y at the same evalPoints, returns a fresh degree-(T-1)
// sharing of X·Y — without any party learning X, Y, or X·Y. Requires N >= 2T-1
// (else the degree-2(T-1) product is underdetermined; TALUS Theorem 10.1).
//
// Method (standard BGW degree reduction):
//  1. local product p_i = x_i·y_i (lies on f_X·f_Y, degree 2(T-1));
//  2. each party deals a FRESH degree-(T-1) re-share of p_i;
//  3. recombine with the degree-2(T-1) Lagrange-at-0 weights over all N points.
func (f *Field) MulShares(x, y, evalPoints []Elem, threshold int, rng io.Reader) ([]Elem, error) {
	n := len(evalPoints)
	if len(x) != n || len(y) != n {
		return nil, ErrShape
	}
	if n < 2*threshold-1 {
		return nil, ErrNotEnoughParties
	}
	reshares := make([][]Elem, n)
	for i := 0; i < n; i++ {
		p := f.Mul(x[i], y[i])
		q, err := f.ShareScalar(p, evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		reshares[i] = q
	}
	return f.recombineReshares(reshares, f.reduceWeights(evalPoints), n), nil
}

// SharedRandomBit generates a degree-(threshold-1) sharing of a uniform bit
// b ∈ {0,1} via XOR-folding per-party private bits: b = b_0 ⊕ … ⊕ b_{N-1}, each
// u⊕v = u + v − 2uv being one secure multiplication. Uniform as long as >= 1
// party's bit is uniform and private (honest majority). Sqrt-free; exercises the
// multiplication substrate exactly as the CSCP carry circuit does. partyBits are
// the parties' private input bits (one per party).
//
// SEMI-HONEST: it trusts each partyBit to be a genuine bit. The malicious layer
// (bitcheck.go) proves b_p·(b_p−1)=0 on each contributed bit before folding.
func (f *Field) SharedRandomBit(evalPoints []Elem, threshold int, partyBits []bool, rng io.Reader) ([]Elem, error) {
	n := len(evalPoints)
	if len(partyBits) != n {
		return nil, ErrShape
	}
	if n < 2*threshold-1 {
		return nil, ErrNotEnoughParties
	}
	bitShares := make([][]Elem, n)
	for h := 0; h < n; h++ {
		var bit Elem
		if partyBits[h] {
			bit = 1
		}
		sh, err := f.ShareScalar(bit, evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		bitShares[h] = sh
	}
	acc := bitShares[0]
	for h := 1; h < n; h++ {
		prod, err := f.MulShares(acc, bitShares[h], evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		sum, err := f.AddShares(acc, bitShares[h])
		if err != nil {
			return nil, err
		}
		twoProd := f.ScalarMulShares(2, prod)
		acc, _ = f.SubShares(sum, twoProd) // sum − 2·prod
	}
	return acc, nil
}
