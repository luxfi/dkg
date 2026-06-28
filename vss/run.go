// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"fmt"
	"io"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/ring"
	"github.com/luxfi/dkg/transcript"
)

// run.go — the in-process orchestrator and the cross-party gate helpers.
//
// RunDKG drives every party through the three rounds in one process. It is the
// reference path (and the test harness) for the distributed deployment, where
// each party runs its own Party over an authenticated network. The transcript
// bytes are independent of which side runs the loop, because every input is a
// deterministic function of the Round-1 outputs and the committee list.

// Result is the public outcome of a DKG run. GroupKey is the dealerless group
// public key. Shares maps each party index to its retained secret share s_j —
// exposed by the in-process reference so a test can validate correctness; in a
// distributed deployment each party holds ONLY its own entry. Transcript is the
// chain-committable digest. CommitDigests[i] is dealer i's equivocation digest.
//
// No field holds the master secret s1 — Shares are the per-party Shamir shares,
// from which s1 is recoverable only by an explicit out-of-band Lagrange combine
// that this package never performs.
type Result struct {
	GroupKey      *ring.GroupPublicKey
	Shares        map[int]ring.Vector // s_j per party (Shamir shares of s1)
	Blinds        map[int]ring.Vector // u_j per party (Shamir shares of u)
	Transcript    [32]byte
	CommitDigests [][32]byte
}

// RunDKG executes the honest-path dealerless DKG for an n-party committee with
// threshold t. identities[i] is party i's long-term keypair; nodes[i] its
// NodeID. context binds the run to an era/committee root. rng drives all
// sampling and encapsulation.
//
// It performs, in order: Round 1 (commit & deal), commit-then-reveal
// verification (component 8), the equivocation gate (component 5), and Round 3
// (verify & aggregate, component 6) for every party. Any deviation surfaces as
// an error; in the honest path none occur.
func RunDKG(
	profile *ring.Profile,
	n, t int,
	identities []*channel.IdentityKey,
	nodes []channel.NodeID,
	context [32]byte,
	rng io.Reader,
) (*Result, error) {
	if len(identities) != n || len(nodes) != n {
		return nil, ErrShape
	}
	dir, err := buildDirectory(identities, nodes)
	if err != nil {
		return nil, err
	}

	// Construct parties.
	parties := make([]*Party, n)
	for i := 0; i < n; i++ {
		p, err := NewParty(profile, nodes[i], identities[i], i, n, t, nodes, dir, context)
		if err != nil {
			return nil, err
		}
		parties[i] = p
	}

	// Round 1.
	r1 := make([]*Round1Out, n)
	for i := 0; i < n; i++ {
		out, err := parties[i].Round1(rng)
		if err != nil {
			return nil, fmt.Errorf("party %d Round1: %w", i, err)
		}
		r1[i] = out
	}

	// Commit-then-reveal verification (component 8): every dealer's revealed
	// commit bytes must match the commitment it broadcast before reveal.
	for i := 0; i < n; i++ {
		revealBytes, nonce := parties[i].Reveal()
		if !channel.VerifyOpening(r1[i].Commitment, channel.Opening{Payload: revealBytes, Nonce: nonce}) {
			return nil, fmt.Errorf("party %d: commit-then-reveal opening invalid", i)
		}
	}

	// Equivocation gate (component 5): each recipient computes a digest of each
	// dealer's commits; in the honest path every recipient sees the same
	// commits, so all digests agree. DetectEquivocation flags any disagreement.
	digestsByRecipient := make(map[int]map[int][32]byte, n)
	for j := 0; j < n; j++ {
		row := make(map[int][32]byte, n)
		for i := 0; i < n; i++ {
			row[i] = parties[j].CommitDigest(r1[i].Commits)
		}
		digestsByRecipient[j] = row
	}
	if bad := DetectEquivocation(digestsByRecipient, n); len(bad) != 0 {
		return nil, fmt.Errorf("%w: dealers %v", ErrEquivocation, bad)
	}
	commitDigests := make([][32]byte, n)
	for i := 0; i < n; i++ {
		commitDigests[i] = parties[0].CommitDigest(r1[i].Commits)
	}

	// Round 3: each party opens its envelopes, verifies, aggregates.
	shares := make(map[int]ring.Vector, n)
	blindShares := make(map[int]ring.Vector, n)
	var groupKey *ring.GroupPublicKey
	for j := 0; j < n; j++ {
		inputs := make(map[int]*DealerInput, n)
		for i := 0; i < n; i++ {
			share, blind, err := parties[j].OpenDealerShare(i, r1[i].Envelopes[j])
			if err != nil {
				return nil, fmt.Errorf("party %d open dealer %d: %w", j, i, err)
			}
			inputs[i] = &DealerInput{Commits: r1[i].Commits, Share: share, Blind: blind}
		}
		res, fault, err := parties[j].Round3(inputs)
		if err != nil {
			if fault != nil {
				return nil, fmt.Errorf("party %d Round3: %w (dealer %d)", j, err, fault.DealerIndex)
			}
			return nil, fmt.Errorf("party %d Round3: %w", j, err)
		}
		shares[j] = res.Share
		blindShares[j] = res.Blind
		if groupKey == nil {
			groupKey = res.GroupKey
		}
	}

	// Transcript: bind the committee, threshold, commit digests, and group key.
	tr := transcript.NewWithDomain(transcript.FuncName, tagTranscript)
	tr.AppendU32("n", uint32(n)).AppendU32("t", uint32(t))
	tr.Append("scheme", []byte(profile.Name))
	for i := 0; i < n; i++ {
		tr.AppendHash("commit", commitDigests[i])
	}
	tr.Append("gpk", groupKey.Encode())

	return &Result{
		GroupKey:      groupKey,
		Shares:        shares,
		Blinds:        blindShares,
		Transcript:    tr.Hash(),
		CommitDigests: commitDigests,
	}, nil
}

// DetectEquivocation cross-checks the commit digests recipients computed for
// each dealer. digestsByRecipient[recipient][dealer] is the digest recipient
// computed over the commits it received from dealer. A dealer that delivered
// different commit vectors to different recipients yields disagreeing digests
// and is flagged. Returns the set of equivocating dealer indices (empty in the
// honest path). Every honest party that sees the same digest matrix computes
// the same flagged set (deterministic adjudication, component 5).
func DetectEquivocation(digestsByRecipient map[int]map[int][32]byte, n int) map[int]bool {
	bad := make(map[int]bool)
	for dealer := 0; dealer < n; dealer++ {
		var ref [32]byte
		haveRef := false
		for recipient := 0; recipient < n; recipient++ {
			row, ok := digestsByRecipient[recipient]
			if !ok {
				continue
			}
			d, ok := row[dealer]
			if !ok {
				continue
			}
			if !haveRef {
				ref = d
				haveRef = true
				continue
			}
			if d != ref {
				bad[dealer] = true
				break
			}
		}
	}
	return bad
}

// buildDirectory assembles an IdentityDirectory from parallel identity/node
// slices.
func buildDirectory(identities []*channel.IdentityKey, nodes []channel.NodeID) (channel.IdentityDirectory, error) {
	entries := make(map[channel.NodeID]*channel.IdentityPublicKey, len(nodes))
	for i := range nodes {
		if identities[i] == nil {
			return nil, ErrMissingIdentity
		}
		entries[nodes[i]] = identities[i].PublicKey()
	}
	return channel.NewIdentityDirectory(entries)
}
