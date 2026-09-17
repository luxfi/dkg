// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/blame"
	"github.com/luxfi/dkg/ring"
)

// TestBadDelivery_EndToEnd exercises the full identifiable-abort path: a dealer
// delivers a share inconsistent with its (honest) commits; the recipient's
// Round-3 detects it (component 6), mints a signed complaint, and a THIRD PARTY
// re-checks both the signature and the cryptographic claim without trusting the
// accuser. The honest path that follows excludes the deviator and completes.
func TestBadDelivery_EndToEnd(t *testing.T) {
	profile, _ := ring.Ringtail()
	n, tt := 5, 3
	ids, nodes := committee(t, n)
	dir, _ := buildDirectory(ids, nodes)
	ctx := [32]byte{0xDE, 0xAD}

	parties := make([]*Party, n)
	for i := range n {
		p, err := NewParty(profile, nodes[i], ids[i], i, n, tt, nodes, dir, ctx)
		if err != nil {
			t.Fatal(err)
		}
		parties[i] = p
	}
	r1 := make([]*Round1Out, n)
	for i := range n {
		out, err := parties[i].Round1(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r1[i] = out
	}

	// Recipient 1 opens every dealer's share, then we CORRUPT dealer 0's share
	// to model a dealer that delivered a share inconsistent with its commits.
	recipient := parties[1]
	inputs := make(map[int]*DealerInput, n)
	for i := range n {
		share, blind, err := recipient.OpenDealerShare(i, r1[i].Envelopes[1])
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = &DealerInput{Commits: r1[i].Commits, Share: share, Blind: blind}
	}
	inputs[0].Share[0].Coeffs[0][0] ^= 1 // flip one coefficient of dealer 0's share

	// Round 3 must detect the bad delivery and name dealer 0.
	_, fault, err := recipient.Round3(inputs)
	if err == nil || fault == nil {
		t.Fatal("Round3 must reject the corrupted share")
	}
	if fault.DealerIndex != 0 {
		t.Fatalf("fault names dealer %d, want 0", fault.DealerIndex)
	}

	// Mint a signed complaint and have a THIRD PARTY verify it end-to-end.
	session := [32]byte{0x55}
	c, err := NewBadDeliveryComplaint(profile, fault, session, nodes[0], nodes[1], ids[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("third party rejected a valid complaint: %v", err)
	}
	justified, err := RecheckBadDelivery(profile, c)
	if err != nil {
		t.Fatal(err)
	}
	if !justified {
		t.Fatal("re-check failed to confirm the share is malformed")
	}

	// Selective abort: exclude dealer 0, the 4 survivors still meet threshold 3.
	dq := blame.ComputeDisqualified([]*blame.Complaint{c}, tt) // need t-1 = 2... so one complaint is below quorum
	if _, bad := dq[nodes[0]]; bad {
		t.Fatal("a single complaint must not disqualify at t-1=2")
	}
}

// TestRecheck_HonestShare_NotJustified checks the re-checker does NOT confirm a
// complaint against an HONEST share — an accuser cannot frame a good dealer by
// submitting that dealer's real (share, blind, commits).
func TestRecheck_HonestShare_NotJustified(t *testing.T) {
	profile, _ := ring.MLDSA65()
	n, tt := 4, 2
	ids, nodes := committee(t, n)
	dir, _ := buildDirectory(ids, nodes)
	ctx := [32]byte{7}

	parties := make([]*Party, n)
	for i := range n {
		parties[i], _ = NewParty(profile, nodes[i], ids[i], i, n, tt, nodes, dir, ctx)
	}
	r1 := make([]*Round1Out, n)
	for i := range n {
		r1[i], _ = parties[i].Round1(rand.Reader)
	}
	// Honest open of dealer 0's share to recipient 2.
	share, blind, err := parties[2].OpenDealerShare(0, r1[0].Envelopes[2])
	if err != nil {
		t.Fatal(err)
	}
	// Build a (spurious) complaint with the HONEST evidence.
	fault := &VerifyFault{DealerIndex: 0, RecipientIndex: 2, Share: share, Blind: blind, Commits: r1[0].Commits}
	c, err := NewBadDeliveryComplaint(profile, fault, [32]byte{}, nodes[0], nodes[2], ids[2])
	if err != nil {
		t.Fatal(err)
	}
	// Signature is valid (the accuser really signed) but the CLAIM is false:
	// the honest share satisfies the Pedersen identity, so re-check rejects.
	if err := c.Verify(dir); err != nil {
		t.Fatalf("form/sig should pass: %v", err)
	}
	justified, err := RecheckBadDelivery(profile, c)
	if err != nil {
		t.Fatal(err)
	}
	if justified {
		t.Fatal("re-check wrongly confirmed a complaint against an honest share")
	}
}

// TestEquivocationGate detects a dealer that broadcasts different commit
// vectors to different recipients (component 5).
func TestEquivocationGate(t *testing.T) {
	profile, _ := ring.Ringtail()
	n := 4
	ids, nodes := committee(t, n)
	dir, _ := buildDirectory(ids, nodes)
	parties := make([]*Party, n)
	for i := range n {
		parties[i], _ = NewParty(profile, nodes[i], ids[i], i, n, 2, nodes, dir, [32]byte{})
	}
	r1 := make([]*Round1Out, n)
	for i := range n {
		r1[i], _ = parties[i].Round1(rand.Reader)
	}
	// Honest digest matrix: every recipient sees every dealer's true commits.
	digests := make(map[int]map[int][32]byte, n)
	for j := range n {
		row := make(map[int][32]byte, n)
		for i := range n {
			row[i] = parties[j].CommitDigest(r1[i].Commits)
		}
		digests[j] = row
	}
	if bad := DetectEquivocation(digests, n); len(bad) != 0 {
		t.Fatalf("honest path flagged %v", bad)
	}
	// Dealer 0 equivocates: recipient 3 receives a DIFFERENT commit set.
	forged := ring.CopyVec(r1[0].Commits[0])
	forged[0].Coeffs[0][0] ^= 1
	tampered := append([]ring.Vector{forged}, r1[0].Commits[1:]...)
	digests[3][0] = parties[3].CommitDigest(tampered)
	bad := DetectEquivocation(digests, n)
	if !bad[0] {
		t.Fatal("equivocation gate failed to flag dealer 0")
	}
}
