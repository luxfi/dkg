// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"encoding/binary"

	"github.com/luxfi/dkg/blame"
	"github.com/luxfi/dkg/channel"
)

// blame_bridge.go — the mpc ↔ blame bridge, the scalar-field analogue of
// vss/blame.go. The blame package owns the complaint machinery (structure,
// signatures, selective-abort) and stays scheme-agnostic; the cryptographic
// CLAIM re-check (does this committed re-share really fail the degree test? does
// this opening really fail to open its commitment?) needs the field math, so it
// lives here. Dependency edge stays one-way: mpc → blame, never the reverse.
//
// Every re-check binds the ACCUSED to the evidence via the accused's own
// signature over the broadcast commitment (CtxBroadcast), then re-runs the
// scalar math, so a third party confirms the deviation WITHOUT trusting the
// accuser — exactly the property vss.RecheckBadDelivery gives the DKG.

// encodeElem serializes one field element to 8 big-endian bytes (evidence wire).
func encodeElem(v Elem) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// ── closer (a): re-share ─────────────────────────────────────────────────────

// NewReshareComplaint mints a signed ReasonBadReshare complaint from a
// ReshareFault. The evidence carries (commit, nonce, shares, dealerSig); the
// dealer's signature binds it to the committed re-share. accuserIdentity signs
// the complaint envelope.
func NewReshareComplaint(fault *ReshareFault, session [32]byte, accused, accuser channel.NodeID, accuserIdentity *channel.IdentityKey) (*blame.Complaint, error) {
	c := &blame.Complaint{
		Session:  session,
		Accused:  accused,
		Accuser:  accuser,
		Reason:   blame.ReasonBadReshare,
		Point:    uint64(fault.Dealer + 1),
		Evidence: blame.BadReshareEvidence(fault.Commit, fault.Nonce, encodeShares(fault.Shares), fault.Sig),
	}
	if err := c.Sign(accuserIdentity); err != nil {
		return nil, err
	}
	return c, nil
}

// RecheckReshare re-checks a ReasonBadReshare complaint against the public
// committee parameters: the accused signed the commitment (CtxBroadcast), the
// commitment binds the shares, and the shares are NOT a degree-(threshold-1)
// codeword. Returns true iff the accusation is justified (all three hold).
func (f *Field) RecheckReshare(dir channel.IdentityDirectory, c *blame.Complaint, evalPoints []Elem, threshold int) (bool, error) {
	commit, nonce, sharesB, sig, err := blame.ParseBadReshareEvidence(c.Evidence)
	if err != nil {
		return false, err
	}
	pub := dir.Get(c.Accused)
	if pub == nil || !channel.Verify(pub, channel.CtxBroadcast, commit, sig) {
		return false, nil // accused did not sign this commitment — not justified
	}
	shares, err := decodeShares(sharesB)
	if err != nil {
		return false, err
	}
	if !equalConst(commit, CommitReshare(shares, nonce)) {
		return false, nil // commitment does not bind these shares — not justified
	}
	return !f.CheckDegree(evalPoints, shares, threshold), nil
}

// ── closer (b): bit validity ─────────────────────────────────────────────────

// NewBitComplaint mints a signed ReasonBadBit complaint from a BitFault. Evidence
// carries the party's committed bit-sharing (commit, nonce, shares, partySig).
func NewBitComplaint(fault *BitFault, session [32]byte, accused, accuser channel.NodeID, accuserIdentity *channel.IdentityKey) (*blame.Complaint, error) {
	c := &blame.Complaint{
		Session:  session,
		Accused:  accused,
		Accuser:  accuser,
		Reason:   blame.ReasonBadBit,
		Point:    uint64(fault.Party + 1),
		Evidence: blame.BadBitEvidence(fault.Commit, fault.Nonce, encodeShares(fault.Shares), fault.Sig),
	}
	if err := c.Sign(accuserIdentity); err != nil {
		return nil, err
	}
	return c, nil
}

// RecheckBit re-checks a ReasonBadBit complaint: the accused signed the
// commitment, the commitment binds the bit-sharing, and the reconstructed secret
// b is NOT in {0,1} (b·(b-1) != 0 mod q). Reconstructing b is sound here because
// the bit belongs to a DEAD computation (the batch check already failed and the
// signing nonce is discarded). Returns true iff the accusation is justified.
func (f *Field) RecheckBit(dir channel.IdentityDirectory, c *blame.Complaint, evalPoints []Elem, threshold int) (bool, error) {
	commit, nonce, sharesB, sig, err := blame.ParseBadBitEvidence(c.Evidence)
	if err != nil {
		return false, err
	}
	pub := dir.Get(c.Accused)
	if pub == nil || !channel.Verify(pub, channel.CtxBroadcast, commit, sig) {
		return false, nil
	}
	shares, err := decodeShares(sharesB)
	if err != nil {
		return false, err
	}
	if !equalConst(commit, CommitBit(shares, nonce)) {
		return false, nil
	}
	if len(evalPoints) < threshold || len(shares) < threshold {
		return false, ErrShape
	}
	b, err := f.Reconstruct(evalPoints[:threshold], shares[:threshold])
	if err != nil {
		return false, err
	}
	// b·(b-1) != 0  ⇔  b ∉ {0,1}.
	return f.Mul(b, f.Sub(b, 1)) != 0, nil
}

// ── closer (c): opening equivocation ─────────────────────────────────────────

// NewOpeningComplaint mints a signed ReasonBadOpening complaint from an
// OpeningFault. Evidence carries (commit, share, nonce, partySig): the party
// signed commit but revealed a (share, nonce) that does not open it.
func NewOpeningComplaint(fault *OpeningFault, session [32]byte, accused, accuser channel.NodeID, accuserIdentity *channel.IdentityKey) (*blame.Complaint, error) {
	c := &blame.Complaint{
		Session:  session,
		Accused:  accused,
		Accuser:  accuser,
		Reason:   blame.ReasonBadOpening,
		Point:    uint64(fault.Party + 1),
		Evidence: blame.BadOpeningEvidence(fault.Commit, encodeElem(fault.Share), fault.Nonce, fault.Sig),
	}
	if err := c.Sign(accuserIdentity); err != nil {
		return nil, err
	}
	return c, nil
}

// RecheckOpening re-checks a ReasonBadOpening complaint: the accused signed the
// commitment (CtxBroadcast) and the revealed (share, nonce) does NOT open it
// (commitment binding violated = equivocation). Returns true iff justified.
func RecheckOpening(dir channel.IdentityDirectory, c *blame.Complaint) (bool, error) {
	commit, shareB, nonce, sig, err := blame.ParseBadOpeningEvidence(c.Evidence)
	if err != nil {
		return false, err
	}
	pub := dir.Get(c.Accused)
	if pub == nil || !channel.Verify(pub, channel.CtxBroadcast, commit, sig) {
		return false, nil
	}
	if len(shareB) < 8 {
		return false, ErrShape
	}
	share := binary.BigEndian.Uint64(shareB[:8])
	// Equivocation iff the revealed opening does NOT reproduce the committed
	// digest (a party that opens honestly reproduces it; one that swaps its
	// share cannot, by binding).
	return !equalConst(commit, CommitOpening(share, nonce)), nil
}
