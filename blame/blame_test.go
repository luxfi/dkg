// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blame

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/channel"
)

func ids(t *testing.T, n int) ([]*channel.IdentityKey, []channel.NodeID, channel.IdentityDirectory) {
	t.Helper()
	keys := make([]*channel.IdentityKey, n)
	nodes := make([]channel.NodeID, n)
	entries := make(map[channel.NodeID]*channel.IdentityPublicKey, n)
	for i := 0; i < n; i++ {
		k, err := channel.GenerateIdentity(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
		nodes[i] = channel.NodeID{byte(i + 1)}
		entries[nodes[i]] = k.PublicKey()
	}
	dir, _ := channel.NewIdentityDirectory(entries)
	return keys, nodes, dir
}

// TestComplaint_SignVerify checks a signed complaint passes third-party form +
// signature verification, and that tampering / forgery / self-accusation fail.
func TestComplaint_SignVerify(t *testing.T) {
	keys, nodes, dir := ids(t, 3)
	c := &Complaint{
		Session:  [32]byte{1, 2, 3},
		Accused:  nodes[0],
		Accuser:  nodes[1],
		Reason:   ReasonMissing, // empty evidence is valid for missing
		Point:    2,
		Evidence: nil,
	}
	if err := c.Sign(keys[1]); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("valid complaint rejected: %v", err)
	}
	// Tampered field invalidates the signature.
	c.Point = 3
	if err := c.Verify(dir); err != ErrComplaintNoSig {
		t.Fatalf("tampered complaint: err = %v, want ErrComplaintNoSig", err)
	}
	// Self-accusation rejected structurally.
	c2 := &Complaint{Session: [32]byte{}, Accused: nodes[0], Accuser: nodes[0], Reason: ReasonMissing, Sig: []byte{1}}
	if err := c2.VerifyForm(); err != ErrComplaintSelfAcc {
		t.Fatalf("self-accusation: err = %v, want ErrComplaintSelfAcc", err)
	}
	// Unknown accuser rejected at signature stage.
	c3 := &Complaint{Session: [32]byte{}, Accused: nodes[0], Accuser: channel.NodeID{0xFF}, Reason: ReasonMissing}
	_ = c3.Sign(keys[2])
	if err := c3.VerifySignature(dir); err != ErrComplaintNoSig {
		t.Fatalf("unknown accuser: err = %v, want ErrComplaintNoSig", err)
	}
}

// TestEvidenceShapes checks per-reason field-count enforcement and the
// cross-reason relabel resistance.
func TestEvidenceShapes(t *testing.T) {
	share := bytes.Repeat([]byte{1}, 64)
	blind := bytes.Repeat([]byte{2}, 64)
	commits := bytes.Repeat([]byte{3}, 64)
	sig := bytes.Repeat([]byte{4}, 64)

	bad := BadDeliveryEvidence(share, blind, commits)
	if err := validateEvidence(ReasonBadDelivery, bad); err != nil {
		t.Fatalf("bad-delivery evidence rejected: %v", err)
	}
	// Relabel resistance: bad-delivery (3 fields) is invalid as equivocation (4).
	if err := validateEvidence(ReasonEquivocation, bad); err != ErrEvidenceFields {
		t.Fatalf("relabel: err = %v, want ErrEvidenceFields", err)
	}
	// Equivocation needs DISTINCT commits.
	eqDup := EquivocationEvidence(commits, commits, sig, sig)
	if err := validateEvidence(ReasonEquivocation, eqDup); err != ErrEvidenceDuplicate {
		t.Fatalf("duplicate commits: err = %v, want ErrEvidenceDuplicate", err)
	}
	eqOK := EquivocationEvidence(commits, bytes.Repeat([]byte{9}, 64), sig, sig)
	if err := validateEvidence(ReasonEquivocation, eqOK); err != nil {
		t.Fatalf("valid equivocation rejected: %v", err)
	}
	// Missing must be empty.
	if err := validateEvidence(ReasonMissing, []byte{1}); err != ErrComplaintForm {
		t.Fatalf("non-empty missing: err = %v", err)
	}
}

// TestSelectiveAbort checks the deterministic disqualification quorum and the
// exclude-and-continue / abort decision (component 7).
func TestSelectiveAbort(t *testing.T) {
	_, nodes, _ := ids(t, 5)
	dealer := nodes[0]
	threshold := 4 // need t-1 = 3 distinct accusers

	mk := func(accuser channel.NodeID) *Complaint {
		return &Complaint{Session: [32]byte{}, Accused: dealer, Accuser: accuser, Reason: ReasonMissing}
	}

	// 2 distinct accusers: below quorum, not disqualified.
	dq := ComputeDisqualified([]*Complaint{mk(nodes[1]), mk(nodes[2])}, threshold)
	if _, bad := dq[dealer]; bad {
		t.Fatal("2 accusers should NOT disqualify at threshold 4")
	}
	// Same accuser repeated: still counts once.
	dq = ComputeDisqualified([]*Complaint{mk(nodes[1]), mk(nodes[1]), mk(nodes[1])}, threshold)
	if _, bad := dq[dealer]; bad {
		t.Fatal("repeated single accuser must not manufacture a quorum")
	}
	// 3 distinct accusers: quorum met.
	dq = ComputeDisqualified([]*Complaint{mk(nodes[1]), mk(nodes[2]), mk(nodes[3])}, threshold)
	if _, bad := dq[dealer]; !bad {
		t.Fatal("3 distinct accusers should disqualify at threshold 4")
	}

	// Exclude-and-continue: 5 → 4 survivors, still ≥ threshold 4 → OK.
	surv, err := FilterQualified(nodes, dq, threshold)
	if err != nil {
		t.Fatalf("survivors should suffice: %v", err)
	}
	if len(surv) != 4 {
		t.Fatalf("survivors = %d, want 4", len(surv))
	}
	for _, s := range surv {
		if s == dealer {
			t.Fatal("disqualified dealer present in survivors")
		}
	}
	// If we also disqualify another, 3 survivors < threshold 4 → abort.
	dq[nodes[1]] = struct{}{}
	if _, err := FilterQualified(nodes, dq, threshold); err != ErrInsufficientQuorum {
		t.Fatalf("under-quorum: err = %v, want ErrInsufficientQuorum", err)
	}
}
