// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"encoding/binary"

	"github.com/luxfi/dkg/blame"
	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/ring"
)

// blame.go — the vss ↔ blame bridge. The blame package owns the complaint
// machinery (structure, signatures, selective-abort) and is scheme-agnostic;
// the cryptographic CLAIM re-check (does the share truly fail the Pedersen
// identity?) needs the ring math, so it lives here. This keeps the dependency
// edge one-way: vss → blame, never the reverse.

// NewBadDeliveryComplaint constructs and signs a ReasonBadDelivery complaint
// from a Round-3 VerifyFault. The evidence carries the (share, blind, commits)
// triple the accuser received, so any third party can re-run RecheckBadDelivery
// and confirm the share is malformed without trusting the accuser. session is
// the DKG transcript hash; accused/accuser are the dealer and complainer
// NodeIDs; accuserIdentity signs.
func NewBadDeliveryComplaint(
	profile *ring.Profile,
	fault *VerifyFault,
	session [32]byte,
	accused, accuser channel.NodeID,
	accuserIdentity *channel.IdentityKey,
) (*blame.Complaint, error) {
	n := profile.Ring.N()
	shareBytes := serializeVec(fault.Share, profile.L, n)
	blindBytes := serializeVec(fault.Blind, profile.L, n)
	commitsBytes := serializeCommits(fault.Commits, profile.K, n)
	c := &blame.Complaint{
		Session:  session,
		Accused:  accused,
		Accuser:  accuser,
		Reason:   blame.ReasonBadDelivery,
		Point:    uint64(fault.RecipientIndex + 1),
		Evidence: blame.BadDeliveryEvidence(shareBytes, blindBytes, commitsBytes),
	}
	if err := c.Sign(accuserIdentity); err != nil {
		return nil, err
	}
	return c, nil
}

// RecheckBadDelivery re-checks a ReasonBadDelivery complaint's cryptographic
// claim against the public profile: it deserializes the evidence and re-runs
// the Pedersen identity at the accuser's point. Returns true iff the share is
// INDEED malformed (the identity fails) — i.e. the accusation is justified.
//
// A complete adjudicator ALSO confirms the evidence's commit vector matches the
// dealer's broadcast commits (via the Round-2 equivocation digest), so an
// accuser cannot fabricate a commit set the honest share happens to fail
// against. That cross-check is the consumer's job; here we verify the math.
func RecheckBadDelivery(profile *ring.Profile, c *blame.Complaint) (bool, error) {
	shareBytes, blindBytes, commitsBytes, err := blame.ParseBadDeliveryEvidence(c.Evidence)
	if err != nil {
		return false, err
	}
	n := profile.Ring.N()
	share, err := deserializeVec(profile.Ring, shareBytes, profile.L, n)
	if err != nil {
		return false, err
	}
	blind, err := deserializeVec(profile.Ring, blindBytes, profile.L, n)
	if err != nil {
		return false, err
	}
	commits, err := deserializeCommits(profile.Ring, commitsBytes, profile.K, n)
	if err != nil {
		return false, err
	}
	ok := verifyPedersen(profile, share, blind, commits, c.Point)
	return !ok, nil // accusation justified iff the identity FAILS.
}

// serializeVec packs one length-L standard-form vector into LE-u64 bytes.
func serializeVec(v ring.Vector, L, n int) []byte {
	out := make([]byte, L*n*8)
	off := 0
	for i := 0; i < L; i++ {
		for c := 0; c < n; c++ {
			binary.LittleEndian.PutUint64(out[off:], v[i].Coeffs[0][c])
			off += 8
		}
	}
	return out
}

// deserializeVec reverses serializeVec into a fresh length-L vector over r.
func deserializeVec(r *ring.Ring, b []byte, L, n int) (ring.Vector, error) {
	if len(b) != L*n*8 {
		return nil, errShareWire
	}
	v := ring.NewVec(r, L)
	off := 0
	for i := 0; i < L; i++ {
		for c := 0; c < n; c++ {
			v[i].Coeffs[0][c] = binary.LittleEndian.Uint64(b[off:])
			off += 8
		}
	}
	return v, nil
}

// deserializeCommits reverses serializeCommits into t vectors of K polys.
func deserializeCommits(r *ring.Ring, b []byte, K, n int) ([]ring.Vector, error) {
	if len(b) < 4 {
		return nil, errShareWire
	}
	t := int(binary.BigEndian.Uint32(b[:4]))
	off := 4
	need := 4 + t*K*n*8
	if len(b) != need {
		return nil, errShareWire
	}
	commits := make([]ring.Vector, t)
	for k := 0; k < t; k++ {
		vec := ring.NewVec(r, K)
		for i := 0; i < K; i++ {
			for c := 0; c < n; c++ {
				vec[i].Coeffs[0][c] = binary.LittleEndian.Uint64(b[off:])
				off += 8
			}
		}
		commits[k] = vec
	}
	return commits, nil
}
