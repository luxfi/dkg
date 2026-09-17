// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"io"
	"slices"
)

// shamir.go — degree-(t-1) Shamir secret sharing over GF(q), factored from the
// pulsar reference shamir_gfq.go / talus_mpc.go. The polynomial is f(x) = secret
// + Σ_{d=1}^{t-1} a_d x^d with fresh uniform a_d; the share for a party at
// evaluation point x is f(x). Σ_p λ_p · f(x_p) = secret by Lagrange at 0 over
// any t points.

// ShareScalar deals secret ∈ [0,q) across the parties at evalPoints with a fresh
// degree-(threshold-1) polynomial whose constant term is the secret. Returns
// shares[p] = f(evalPoints[p]). The caller supplies the randomness source so a
// committee run is KAT-reproducible from a master seed.
func (f *Field) ShareScalar(secret Elem, evalPoints []Elem, threshold int, rng io.Reader) ([]Elem, error) {
	if threshold < 1 {
		return nil, ErrInvalidThreshold
	}
	coeffs := make([]Elem, threshold-1)
	for d := 0; d < threshold-1; d++ {
		v, err := f.Rand(rng)
		if err != nil {
			return nil, err
		}
		coeffs[d] = v
	}
	out := make([]Elem, len(evalPoints))
	a0 := secret % f.q
	for p, xp := range evalPoints {
		// Horner: acc = ((…(a_{t-1}·x + a_{t-2})·x + …)·x + a0).
		var acc Elem
		for d := threshold - 2; d >= 0; d-- {
			acc = f.Add(f.Mul(acc, xp), coeffs[d])
		}
		acc = f.Add(f.Mul(acc, xp), a0)
		out[p] = acc
	}
	return out, nil
}

// ShareScalarWithPoly is ShareScalar that also returns the sampled polynomial
// coefficients (constant term = secret, then the t-1 random coefficients). The
// malicious layer needs the coefficients to commit to the re-share polynomial.
func (f *Field) ShareScalarWithPoly(secret Elem, evalPoints []Elem, threshold int, rng io.Reader) (shares []Elem, poly []Elem, err error) {
	if threshold < 1 {
		return nil, nil, ErrInvalidThreshold
	}
	poly = make([]Elem, threshold)
	poly[0] = secret % f.q
	for d := 1; d < threshold; d++ {
		v, e := f.Rand(rng)
		if e != nil {
			return nil, nil, e
		}
		poly[d] = v
	}
	shares = make([]Elem, len(evalPoints))
	for p, xp := range evalPoints {
		shares[p] = f.EvalPoly(poly, xp)
	}
	return shares, poly, nil
}

// EvalPoly evaluates poly(x) = Σ_k poly[k]·x^k by Horner.
func (f *Field) EvalPoly(poly []Elem, x Elem) Elem {
	var acc Elem
	for _, p := range slices.Backward(poly) {
		acc = f.Add(f.Mul(acc, x), p)
	}
	return acc
}

// LagrangeAtZero returns the Lagrange coefficient at X=0 for the party at
// evaluation point myX in the quorum allEvals: λ = Π_{xj≠myX} (-xj)/(myX-xj).
// Computed over PUBLIC eval points, so the divisions (Inv) leak nothing secret.
func (f *Field) LagrangeAtZero(myX Elem, allEvals []Elem) Elem {
	num := Elem(1)
	den := Elem(1)
	for _, xj := range allEvals {
		if xj == myX {
			continue
		}
		num = f.Mul(num, f.Neg(xj))      // ·(-xj)
		den = f.Mul(den, f.Sub(myX, xj)) // ·(myX - xj)
	}
	return f.Mul(num, f.Inv(den))
}

// Reconstruct Lagrange-interpolates a parallel (evalPoints, shares) pair at X=0.
// The caller supplies >= degree+1 points; for a degree-(t-1) sharing that is any
// t points. No bounds beyond shape are enforced here — RECONSTRUCTION IS THE ONE
// PLACE A SECRET LEAVES THE SHARED DOMAIN, so callers gate it (cscp/ opens only
// the three sanctioned leak-free values; the malicious layer cross-checks before
// trusting an open).
func (f *Field) Reconstruct(evalPoints, shares []Elem) (Elem, error) {
	if len(evalPoints) != len(shares) || len(shares) == 0 {
		return 0, ErrShape
	}
	var acc Elem
	for i := range shares {
		lambda := f.LagrangeAtZero(evalPoints[i], evalPoints)
		acc = f.Add(acc, f.Mul(lambda, shares[i]))
	}
	return acc, nil
}

// InterpolateAtZeroSubset reconstructs at X=0 using only the share indices in
// idx (a chosen quorum). evalPoints and shares are the full parallel arrays; idx
// selects which to use. Used by the Reed-Solomon degree / error-detection checks
// in the malicious layer, which interpolate over chosen subsets.
func (f *Field) InterpolateAtZeroSubset(evalPoints, shares []Elem, idx []int) (Elem, error) {
	if len(evalPoints) != len(shares) || len(idx) == 0 {
		return 0, ErrShape
	}
	xs := make([]Elem, len(idx))
	for i, j := range idx {
		xs[i] = evalPoints[j]
	}
	var acc Elem
	for _, j := range idx {
		lambda := f.LagrangeAtZero(evalPoints[j], xs)
		acc = f.Add(acc, f.Mul(lambda, shares[j]))
	}
	return acc, nil
}

// EvalInterpolatedSubset interpolates the degree-(len(idx)-1) polynomial through
// the points {(evalPoints[j], shares[j]) : j ∈ idx} and evaluates it at atX. The
// Reed-Solomon checks use this to predict a held-out party's share from a quorum
// and compare against the dealt value.
func (f *Field) EvalInterpolatedSubset(evalPoints, shares []Elem, idx []int, atX Elem) (Elem, error) {
	if len(evalPoints) != len(shares) || len(idx) == 0 {
		return 0, ErrShape
	}
	// Lagrange interpolation evaluated at atX:
	//   p(atX) = Σ_{i∈idx} shares[i] · Π_{j∈idx, j≠i} (atX - x_j)/(x_i - x_j).
	var acc Elem
	for _, i := range idx {
		xi := evalPoints[i]
		num := Elem(1)
		den := Elem(1)
		for _, j := range idx {
			if j == i {
				continue
			}
			xj := evalPoints[j]
			num = f.Mul(num, f.Sub(atX, xj))
			den = f.Mul(den, f.Sub(xi, xj))
		}
		term := f.Mul(shares[i], f.Mul(num, f.Inv(den)))
		acc = f.Add(acc, term)
	}
	return acc, nil
}
