// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package blame is the identifiable-abort layer for luxfi/dkg: signed,
// publicly-verifiable complaints (component 4) and selective-abort adjudication
// (component 7). Every detected deviation in the DKG produces a Complaint that
// any third party — chain validator, audit observer, slashing module — can
// re-check WITHOUT trusting the complainer:
//
//   - the structural form (field counts, min lengths) is checked here;
//   - the accuser's ML-DSA-65 signature is checked here against the published
//     identity directory;
//   - the cryptographic CLAIM (does the share really fail the Pedersen
//     identity?) is re-checked by the vss layer, which owns the ring math —
//     blame stays scheme-agnostic and carries the evidence as opaque bytes.
//
// Selective-abort: a deviator named by a quorum of distinct accusers is
// excluded; the committee continues with the qualified survivors (or
// re-samples). The chain slashes from the signed evidence. blame depends only
// on channel (identity + signatures) and transcript (canonical encoding) — it
// never imports ring or vss, so there is no cycle and a slashing module can
// link it standalone.
package blame

import (
	"errors"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/transcript"
)

// Reason enumerates the DKG failure modes that justify a complaint.
type Reason uint8

const (
	// ReasonBadDelivery: a private (share, blind) fails the Pedersen identity
	// A·f_i(j)+B·g_i(j)=Σ_k j^k C_{i,k} at the recipient. Evidence: the
	// (share, blind, commits) triple — publicly re-checkable.
	ReasonBadDelivery Reason = 1
	// ReasonEquivocation: a dealer broadcast different commit vectors to
	// different recipients. Evidence: two signed commit-digest broadcasts that
	// disagree.
	ReasonEquivocation Reason = 2
	// ReasonMissing: a dealer failed to deliver by the round deadline. Evidence
	// is empty by design — the absence is the evidence; a liveness round
	// timestamps the deadline.
	ReasonMissing Reason = 3
	// ReasonMalformedCommit: a dealer's commit vector has wrong length /
	// dimension. Evidence: the malformed commit bytes.
	ReasonMalformedCommit Reason = 4
	// ReasonBadReshare: a malicious party fed an inconsistent re-share into a
	// BGW secure multiplication — a hash-committed re-share whose N dealt shares
	// do NOT lie on a degree-(T-1) polynomial (the Reed-Solomon membership test
	// fails). Evidence: the (commit, nonce, shares, dealerSig) tuple — the
	// commitment binds the dealer to a specific N-share vector, and any third
	// party re-runs CheckDegree to confirm it is off-polynomial. Closes CSCP
	// deviation (a). The scalar math re-check lives in mpc.RecheckReshare; blame
	// stays scheme-agnostic.
	ReasonBadReshare Reason = 5
	// ReasonBadOpening: a malicious party equivocated at a reconstruction — it
	// signed a commitment to its opening share, then broadcast a DIFFERENT share
	// (the revealed (share, nonce) does not open the committed digest). Evidence:
	// the (commit, share, nonce, partySig) tuple. Closes CSCP deviation (c). The
	// re-check is mpc.RecheckOpening (commitment binding, not RS decoding — RS
	// error-correction is unsound at N=2T-1 against T-1 malicious parties).
	ReasonBadOpening Reason = 6
	// ReasonBadBit: a malicious party contributed a non-{0,1} value as a private
	// "random bit", skewing a masked value. Evidence: the (commit, nonce, shares,
	// partySig) tuple committing the party's own bit-sharing; the re-check
	// mpc.RecheckBit reconstructs the bit b of the DEAD (already-retried)
	// computation and confirms b·(b-1) != 0 mod q. Closes CSCP deviation (b).
	ReasonBadBit Reason = 7
)

// String returns a human-readable reason name.
func (r Reason) String() string {
	switch r {
	case ReasonBadDelivery:
		return "bad-delivery"
	case ReasonEquivocation:
		return "equivocation"
	case ReasonMissing:
		return "missing"
	case ReasonMalformedCommit:
		return "malformed-commit"
	case ReasonBadReshare:
		return "bad-reshare"
	case ReasonBadOpening:
		return "bad-opening"
	case ReasonBadBit:
		return "bad-bit"
	default:
		return "unknown"
	}
}

// Errors returned by blame operations.
var (
	ErrComplaintForm      = errors.New("dkg/blame: complaint structurally invalid")
	ErrComplaintSelfAcc   = errors.New("dkg/blame: accuser equals accused")
	ErrComplaintReason    = errors.New("dkg/blame: complaint reason out of range")
	ErrComplaintNoSig     = errors.New("dkg/blame: complaint signature missing or invalid")
	ErrComplaintNoEv      = errors.New("dkg/blame: complaint evidence missing")
	ErrEvidenceFields     = errors.New("dkg/blame: evidence field count wrong for reason")
	ErrEvidenceDuplicate  = errors.New("dkg/blame: evidence fields equal where they must differ")
	ErrInsufficientQuorum = errors.New("dkg/blame: qualified survivors below threshold after exclusion")
)

// ctxComplaint is the ML-DSA signing context for complaints, re-exported from
// channel so blame and channel agree on the domain tag.
const ctxComplaint = channel.CtxComplaint

// Complaint is a signed assertion that Accused misbehaved during one DKG
// session. Accuser signs the canonical bytes under its long-term ML-DSA-65
// identity. Session binds the complaint to a specific DKG invocation (a stale
// session hash is rejected). Point is the accuser's Shamir evaluation point,
// needed to re-check a ReasonBadDelivery claim.
type Complaint struct {
	Session  [32]byte       // DKG session transcript hash
	Accused  channel.NodeID // the misbehaving dealer
	Accuser  channel.NodeID // the complainer (signer)
	Reason   Reason         //
	Point    uint64         // accuser evaluation point (recipient index + 1)
	Evidence []byte         // canonical TLV evidence (see evidence.go)
	Sig      []byte         // ML-DSA-65 over SigningBytes() by Accuser
}

// SigningBytes returns the canonical to-be-signed bytes of a complaint
// (signature excluded). TupleHash256-framed so two distinct complaints can
// never share a pre-image.
func (c *Complaint) SigningBytes() []byte {
	t := transcript.NewWithDomain(transcript.FuncName, "LUX-DKG-COMPLAINT-V1")
	t.AppendHash("session", c.Session)
	t.Append("accused", c.Accused[:])
	t.Append("accuser", c.Accuser[:])
	t.Append("reason", []byte{byte(c.Reason)})
	t.AppendU64("point", c.Point)
	t.Append("evidence", c.Evidence)
	h := t.Hash()
	return h[:]
}

// Sign signs the complaint under the accuser's long-term identity key.
func (c *Complaint) Sign(accuserIdentity *channel.IdentityKey) error {
	sig, err := channel.Sign(accuserIdentity, ctxComplaint, c.SigningBytes())
	if err != nil {
		return err
	}
	c.Sig = sig
	return nil
}

// VerifyForm performs the third-party STRUCTURAL well-formedness check,
// independent of any signature: non-self-accusation, known reason, non-empty
// signature, and the per-reason evidence shape. Call this BEFORE signature
// verification.
func (c *Complaint) VerifyForm() error {
	if c == nil {
		return ErrComplaintForm
	}
	if c.Accuser == c.Accused {
		return ErrComplaintSelfAcc
	}
	switch c.Reason {
	case ReasonBadDelivery, ReasonEquivocation, ReasonMissing, ReasonMalformedCommit,
		ReasonBadReshare, ReasonBadOpening, ReasonBadBit:
	default:
		return ErrComplaintReason
	}
	if len(c.Sig) == 0 {
		return ErrComplaintNoSig
	}
	return validateEvidence(c.Reason, c.Evidence)
}

// VerifySignature checks the accuser's ML-DSA-65 signature against the directory.
// Returns ErrComplaintNoSig if the accuser is unknown or the signature is bad.
func (c *Complaint) VerifySignature(dir channel.IdentityDirectory) error {
	pub := dir.Get(c.Accuser)
	if pub == nil {
		return ErrComplaintNoSig
	}
	if !channel.Verify(pub, ctxComplaint, c.SigningBytes(), c.Sig) {
		return ErrComplaintNoSig
	}
	return nil
}

// Verify performs the full third-party check: structural form THEN signature.
// It does NOT re-check the cryptographic claim (e.g. that the share truly fails
// the Pedersen identity) — that is the vss layer's RecheckBadDelivery, which
// owns the ring math. A complete adjudicator runs both.
func (c *Complaint) Verify(dir channel.IdentityDirectory) error {
	if err := c.VerifyForm(); err != nil {
		return err
	}
	return c.VerifySignature(dir)
}
