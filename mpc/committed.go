// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"crypto/subtle"
	"encoding/binary"
	"io"

	"github.com/luxfi/dkg/transcript"
)

// committed.go — closer (a): committed re-shares with an exact degree check.
//
// WHY A HASH COMMITMENT, NOT THE vss LATTICE PEDERSEN. The DKG's vss Pedersen
// commitment C = A·c + B·r binds only SHORT openings: its binding reduces to
// Module-SIS, which is hard only for a bounded-norm collision (A·Δc + B·Δr = 0
// with ‖(Δc,Δr)‖ small). A BGW re-share over GF(q) shares a FULL-RANGE scalar
// (the local product x_i·y_i and the t-1 uniform Shamir coefficients each span
// [0,q)), so the lattice commitment provides NO binding for it — two full-range
// openings collide through a short kernel vector. The sound, post-quantum,
// full-range-safe primitive is a cSHAKE256 hash commitment: binding via
// collision resistance with no shortness requirement, and no discrete-log group
// (unlike Feldman). This is the one place the substrate deliberately departs
// from the seam suggested in HANDOFF.md, for a load-bearing soundness reason.
//
// WHY THE DEGREE CHECK IS EXACT, NOT REED-SOLOMON ERROR-CORRECTION. The check
// verifies ONE dealer's OWN committed N-share vector against the degree bound.
// Because the dealer committed to the whole vector, CheckDegree is exact for any
// N >= T (no honest-majority decoding needed). Error-correction over a MIXED
// adversarial share set is NOT used — and could not be: at N = 2T-1 a coalition
// of T-1 can present a fake degree-(T-1) polynomial agreeing with 2(T-1) >= T
// shares, out-voting the honest polynomial's T, so RS decoding cannot identify
// the honest value. Identification therefore rests on commitment BINDING (this
// file) plus equivocation detection at opens (openshare.go), never on decoding.

// Commitment / nonce sizing and cSHAKE256 domain customizations. The three
// roles (re-share, opening, bit) live in disjoint cSHAKE domains so a commitment
// minted for one role can never be replayed as another.
const (
	// CommitLen is the byte length of a cSHAKE256 commitment digest.
	CommitLen = 32
	// NonceLen is the byte length of a commitment opening nonce.
	NonceLen = 32

	cShakeFn        = "LUX-DKG-MPC"
	csReshareCommit = "reshare-commit-v1"
	csOpenCommit    = "open-commit-v1"
	csBitCommit     = "bit-commit-v1"
)

// encodeShares serializes an N-share []Elem vector to canonical big-endian bytes
// (8 bytes per share) for hashing and for blame evidence.
func encodeShares(shares []Elem) []byte {
	out := make([]byte, 8*len(shares))
	for i, s := range shares {
		binary.BigEndian.PutUint64(out[8*i:], s)
	}
	return out
}

// decodeShares reverses encodeShares.
func decodeShares(b []byte) ([]Elem, error) {
	if len(b) == 0 || len(b)%8 != 0 {
		return nil, ErrShape
	}
	out := make([]Elem, len(b)/8)
	for i := range out {
		out[i] = binary.BigEndian.Uint64(b[8*i:])
	}
	return out, nil
}

// commitBytes is the role-separated cSHAKE256 commitment to an N-share vector
// under a 32-byte uniform nonce. Binding = collision resistance; hiding = the
// nonce. customization selects the role domain.
func commitBytes(customization string, shares []Elem, nonce []byte) []byte {
	buf := make([]byte, 0, len(nonce)+8*len(shares))
	buf = append(buf, nonce...)
	buf = append(buf, encodeShares(shares)...)
	return transcript.CShake256(buf, CommitLen, cShakeFn, customization)
}

// CommitReshare commits a dealer to its N-share re-share vector (closer a).
func CommitReshare(shares []Elem, nonce []byte) []byte {
	return commitBytes(csReshareCommit, shares, nonce)
}

// NewNonce draws a fresh 32-byte commitment opening nonce.
func NewNonce(rng io.Reader) ([]byte, error) {
	n := make([]byte, NonceLen)
	if _, err := io.ReadFull(rng, n); err != nil {
		return nil, err
	}
	return n, nil
}

// equalConst is a constant-time byte compare (the inputs are public commitment
// digests; constant-time is hygiene, not a leak boundary).
func equalConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// CheckDegree reports whether the N-share vector lies on a polynomial of degree
// < threshold over evalPoints — i.e. whether it is a valid [N, threshold]
// Reed-Solomon codeword (a genuine degree-(threshold-1) Shamir sharing). It
// interpolates the unique degree-<threshold polynomial through the first
// `threshold` shares and verifies every remaining share agrees. EXACT for any
// N >= threshold: if it returns true, all N shares lie on the interpolated
// polynomial; if any dealt share is off, it returns false. (This is a per-dealer
// test of the dealer's OWN committed vector, so no error-correction is needed.)
func (f *Field) CheckDegree(evalPoints, shares []Elem, threshold int) bool {
	n := len(evalPoints)
	if len(shares) != n || threshold < 1 || n < threshold {
		return false
	}
	if n == threshold {
		return true // any threshold points define a unique degree-<threshold poly
	}
	idx := make([]int, threshold)
	for i := range idx {
		idx[i] = i
	}
	for j := threshold; j < n; j++ {
		pred, err := f.EvalInterpolatedSubset(evalPoints, shares, idx, evalPoints[j])
		if err != nil {
			return false
		}
		if pred != shares[j] {
			return false
		}
	}
	return true
}

// ReshareDeal is one dealer's committed degree-(threshold-1) re-share: the N
// dealt shares, the opening nonce, and the binding commitment the dealer
// broadcasts before any share is used.
type ReshareDeal struct {
	Shares []Elem
	Nonce  []byte
	Commit []byte
}

// ReshareFault is the mpc-layer analogue of vss.VerifyFault: publicly
// re-checkable evidence that one dealer's committed re-share is malformed (the
// commitment does not bind the shares, or the shares are off the degree-(T-1)
// code). The blame bridge mints a signed ReasonBadReshare complaint from it.
type ReshareFault struct {
	Dealer     int    // dealer party index (0-based)
	EvalPoints []Elem // committee eval points (public)
	Threshold  int    // sharing threshold T
	Shares     []Elem // the dealer's dealt N-share re-share vector
	Nonce      []byte // commitment opening nonce
	Commit     []byte // CommitReshare(Shares, Nonce) the dealer broadcast
	Sig        []byte // dealer's signature over Commit (set by the protocol/bridge)
}

// DealReshare produces a committed degree-(threshold-1) re-share of secret over
// evalPoints with a fresh nonce and binding commitment.
func (f *Field) DealReshare(secret Elem, evalPoints []Elem, threshold int, rng io.Reader) (*ReshareDeal, error) {
	shares, err := f.ShareScalar(secret, evalPoints, threshold, rng)
	if err != nil {
		return nil, err
	}
	nonce, err := NewNonce(rng)
	if err != nil {
		return nil, err
	}
	return &ReshareDeal{Shares: shares, Nonce: nonce, Commit: CommitReshare(shares, nonce)}, nil
}

// VerifyReshareDeal checks a dealer's re-share before use: the commitment binds
// the shares (re-hash) AND the shares are a degree-(threshold-1) codeword.
func (f *Field) VerifyReshareDeal(d *ReshareDeal, evalPoints []Elem, threshold int) bool {
	if d == nil || !equalConst(d.Commit, CommitReshare(d.Shares, d.Nonce)) {
		return false
	}
	return f.CheckDegree(evalPoints, d.Shares, threshold)
}

// faultFromDeal packages a rejected deal as a ReshareFault.
func faultFromDeal(dealer int, d *ReshareDeal, evalPoints []Elem, threshold int) *ReshareFault {
	return &ReshareFault{
		Dealer: dealer, EvalPoints: evalPoints, Threshold: threshold,
		Shares: d.Shares, Nonce: d.Nonce, Commit: d.Commit,
	}
}

// CombineCommittedReshares verifies each dealer's committed re-share and, if all
// are admissible, recombines them with the degree-2(T-1) Lagrange-at-0 weights
// into a fresh degree-(threshold-1) sharing of the product (BGW degree
// reduction). If ANY dealer's re-share is malformed it returns the first
// ReshareFault (and nil shares) so the caller mints a blame complaint. deals[i]
// is dealer i's committed re-share of its local product p_i = x_i·y_i.
func (f *Field) CombineCommittedReshares(deals []*ReshareDeal, evalPoints []Elem, threshold int) ([]Elem, *ReshareFault, error) {
	n := len(evalPoints)
	if len(deals) != n {
		return nil, nil, ErrShape
	}
	if n < 2*threshold-1 {
		return nil, nil, ErrNotEnoughParties
	}
	for i, d := range deals {
		if d == nil || len(d.Shares) != n {
			return nil, nil, ErrShape
		}
		if !equalConst(d.Commit, CommitReshare(d.Shares, d.Nonce)) {
			return nil, faultFromDeal(i, d, evalPoints, threshold), nil
		}
		if !f.CheckDegree(evalPoints, d.Shares, threshold) {
			return nil, faultFromDeal(i, d, evalPoints, threshold), nil
		}
	}
	reshares := make([][]Elem, n)
	for i := range deals {
		reshares[i] = deals[i].Shares
	}
	return f.recombineReshares(reshares, f.reduceWeights(evalPoints), n), nil, nil
}

// MulSharesCommitted is the malicious-secure BGW secure multiplication: each
// party deals a COMMITTED degree-(threshold-1) re-share of its local product
// x_i·y_i, every re-share is degree-checked before use, and the result is the
// recombined product sharing. On honest input it equals MulShares; a malformed
// re-share is rejected with a ReshareFault. Requires N >= 2T-1.
func (f *Field) MulSharesCommitted(x, y, evalPoints []Elem, threshold int, rng io.Reader) ([]Elem, *ReshareFault, error) {
	n := len(evalPoints)
	if len(x) != n || len(y) != n {
		return nil, nil, ErrShape
	}
	if n < 2*threshold-1 {
		return nil, nil, ErrNotEnoughParties
	}
	deals := make([]*ReshareDeal, n)
	for i := 0; i < n; i++ {
		d, err := f.DealReshare(f.Mul(x[i], y[i]), evalPoints, threshold, rng)
		if err != nil {
			return nil, nil, err
		}
		deals[i] = d
	}
	return f.CombineCommittedReshares(deals, evalPoints, threshold)
}
