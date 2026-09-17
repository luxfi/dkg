// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"errors"
	"io"
	"math/bits"

	"github.com/luxfi/dkg/ring"
)

// Elem is one field element: the canonical representative in [0, q) of a GF(q)
// residue. Shamir shares, evaluation points, and secrets are all Elems. A
// length-N []Elem indexed by party is a sharing (parallel to the eval points).
type Elem = uint64

// Errors returned by the field / substrate.
var (
	// ErrFieldModulus rejects a modulus outside the supported range. q must be
	// an odd prime in [3, 2^62); the upper bound keeps a+b < 2^63 (no overflow
	// in the branchless conditional subtract) and a·b's high word < q (the
	// bits.Div64 precondition).
	ErrFieldModulus = errors.New("dkg/mpc: field modulus must be an odd prime in [3, 2^62)")
	// ErrInvalidThreshold mirrors the foundation's threshold guard.
	ErrInvalidThreshold = errors.New("dkg/mpc: invalid threshold (need t >= 1)")
	// ErrShape rejects mismatched share / eval-point shapes.
	ErrShape = errors.New("dkg/mpc: share / eval-point shape mismatch")
	// ErrNotEnoughParties is the TALUS Theorem 10.1 barrier: a degree-reducing
	// multiplication needs N >= 2T-1 so the degree-2(T-1) product is
	// reconstructable (and, in the malicious layer, so Reed-Solomon detection
	// identifies up to T-1 corruptions).
	ErrNotEnoughParties = errors.New(
		"dkg/mpc: BGW multiplication needs N >= 2T-1 (honest majority) — the " +
			"degree-2(T-1) product of two degree-(T-1) sharings is otherwise " +
			"unreconstructable (TALUS Theorem 10.1)")
	// ErrRandExhausted is returned when rejection sampling cannot draw a value
	// below q within the retry budget (astronomically unlikely).
	ErrRandExhausted = errors.New("dkg/mpc: uniform field sampling exhausted retries")
)

// Field is the prime field GF(q) the BGW substrate and the CSCP circuit operate
// over. It carries the modulus and the bit length of q-1 (the width a residue
// occupies, used by the bit-decomposition in cscp/). All operations keep the
// canonical representative in [0, q).
type Field struct {
	q      uint64
	bitLen int
}

// NewField constructs GF(q). q must be an odd prime in [3, 2^62) (the ring
// guarantees its modulus is an NTT-friendly prime; this only bounds the range
// the substrate arithmetic relies on). Primality is NOT re-checked here — the
// caller's ring profile is the authority — but q must be odd and in range.
func NewField(q uint64) (*Field, error) {
	if q < 3 || q>>62 != 0 || q&1 == 0 {
		return nil, ErrFieldModulus
	}
	return &Field{q: q, bitLen: bits.Len64(q - 1)}, nil
}

// FieldFromProfile builds the GF(q) field whose modulus is the profile's ring
// modulus. The Shamir field IS the ring modulus — the central DRY fact that
// lets the substrate stay scheme-agnostic.
func FieldFromProfile(p *ring.Profile) (*Field, error) {
	if p == nil || p.Ring == nil {
		return nil, ErrFieldModulus
	}
	return NewField(p.Ring.Q())
}

// Q returns the field modulus.
func (f *Field) Q() uint64 { return f.q }

// BitLen returns the bit length of q-1: the number of bits a residue in [0, q)
// occupies. The cscp/ bit-decomposition extracts exactly this many bits.
func (f *Field) BitLen() int { return f.bitLen }

// Reduce maps an arbitrary uint64 into [0, q). Used at the substrate boundary
// where a caller hands in a raw coefficient.
func (f *Field) Reduce(a uint64) Elem { return a % f.q }

// Add returns (a + b) mod q for a, b in [0, q), branchless.
func (f *Field) Add(a, b Elem) Elem { return csub(a+b, f.q) }

// Sub returns (a - b) mod q for a, b in [0, q), branchless.
func (f *Field) Sub(a, b Elem) Elem { return csub(a+f.q-b, f.q) }

// Neg returns (-a) mod q.
func (f *Field) Neg(a Elem) Elem { return csub(f.q-a, f.q) }

// Mul returns (a · b) mod q via a 128-bit product and a single 64-bit divide.
// The high word of a·b is < q for q < 2^48 (Ringtail) and is 0 for q < 2^32
// (ML-DSA), so the bits.Div64 precondition (hi < q) holds for every supported
// modulus.
func (f *Field) Mul(a, b Elem) Elem {
	hi, lo := bits.Mul64(a%f.q, b%f.q)
	_, r := bits.Div64(hi, lo, f.q)
	return r
}

// Pow returns base^exp mod q by square-and-multiply (used only on PUBLIC values:
// Fermat inverse over eval-point differences). Not constant-time over exp; exp
// here is the fixed public q-2 or a public exponent, never a secret.
func (f *Field) Pow(base, exp uint64) Elem {
	result := Elem(1)
	b := base % f.q
	for exp > 0 {
		if exp&1 == 1 {
			result = f.Mul(result, b)
		}
		b = f.Mul(b, b)
		exp >>= 1
	}
	return result
}

// Inv returns a^{-1} mod q via Fermat's little theorem (q prime): a^{q-2}.
// Called only on PUBLIC eval-point differences (Lagrange denominators), never on
// a secret share, so the non-constant-time Pow is safe.
func (f *Field) Inv(a Elem) Elem { return f.Pow(a, f.q-2) }

// Rand draws one uniform field element in [0, q) by rejection sampling on a
// byte-aligned window of ceil(bitLen/8) bytes masked to bitLen bits. The accept
// rate is >= 1/2 (q > 2^{bitLen-1}), so the retry budget is never a concern.
func (f *Field) Rand(rng io.Reader) (Elem, error) {
	nbytes := (f.bitLen + 7) / 8
	mask := (uint64(1) << uint(f.bitLen)) - 1
	buf := make([]byte, nbytes)
	for range 128 {
		if _, err := io.ReadFull(rng, buf); err != nil {
			return 0, err
		}
		var x uint64
		for _, b := range buf {
			x = (x << 8) | uint64(b)
		}
		x &= mask
		if x < f.q {
			return x, nil
		}
	}
	return 0, ErrRandExhausted
}

// RandBit draws one uniform bit from rng.
func RandBit(rng io.Reader) (bool, error) {
	var b [1]byte
	if _, err := io.ReadFull(rng, b[:]); err != nil {
		return false, err
	}
	return b[0]&1 == 1, nil
}

// csub returns x - q if x >= q else x, for x in [0, 2q) with q < 2^63,
// branchless: when x < q the subtraction underflows (top bit set) and q is
// added back; when x >= q the difference is < 2^63 (top bit clear) and nothing
// is added. The branch-freedom means the substrate's field arithmetic reveals
// nothing through timing even though, in honest-majority MPC, a single party's
// shares are already independent of the secret.
func csub(x, q uint64) uint64 {
	x -= q
	x += q & (0 - (x >> 63))
	return x
}
