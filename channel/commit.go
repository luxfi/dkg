// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package channel

import (
	"io"

	"github.com/luxfi/dkg/transcript"
)

// commit.go — commit-then-reveal (DESIGN component 8: last-mover bias control).
//
// In a dealerless DKG the joint key is the sum of every party's contribution.
// A rushing adversary who learns the honest parties' contributions before
// fixing its own can bias the joint output (choose c_adv so the sum lands in a
// chosen set). Commit-then-reveal removes that advantage: every party first
// broadcasts a hiding, binding commitment to its contribution; only after all
// commitments are collected does anyone reveal. The adversary must commit
// before it sees anything, so its contribution is independent of the honest
// parties' — the joint key is unbiased given one honest contributor.
//
// The commitment is a cSHAKE256 hash of (payload ‖ nonce). Hiding: the 32-byte
// nonce makes the commitment indistinguishable from random without the opening
// (cSHAKE256 modelled as a random oracle). Binding: finding a second
// (payload', nonce') for the same commitment is a cSHAKE256 collision.

// commitTag is the SP 800-185 customization for commitments.
const commitTag = "LUX-DKG-COMMIT-REVEAL-V1"

// Commitment is a 32-byte hiding, binding commitment to a contribution.
type Commitment [32]byte

// Opening is the reveal half: the committed payload and its nonce.
type Opening struct {
	Payload []byte
	Nonce   [32]byte
}

// Commit returns a commitment to payload under nonce. The nonce MUST be fresh
// and secret until reveal (use NewNonce). Binds (payload ‖ nonce) so the
// payload boundary is unambiguous via TupleHash framing.
func Commit(payload []byte, nonce [32]byte) Commitment {
	t := transcript.NewWithDomain(transcript.FuncName, commitTag)
	t.Append("payload", payload)
	t.Append("nonce", nonce[:])
	return Commitment(t.Hash())
}

// CommitWith builds the commitment from an Opening.
func CommitWith(o Opening) Commitment { return Commit(o.Payload, o.Nonce) }

// VerifyOpening verifies that o is a valid opening of c, in constant time over
// the 32-byte commitment comparison.
func VerifyOpening(c Commitment, o Opening) bool {
	got := Commit(o.Payload, o.Nonce)
	return ctEqual(got[:], c[:])
}

// NewNonce draws a fresh 32-byte commitment nonce from rng.
func NewNonce(rng io.Reader) ([32]byte, error) {
	var n [32]byte
	if rng == nil {
		return n, ErrShortRand
	}
	if _, err := io.ReadFull(rng, n[:]); err != nil {
		return n, ErrShortRand
	}
	return n, nil
}
