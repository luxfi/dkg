// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blame

import (
	"bytes"
	"sort"

	"github.com/luxfi/dkg/channel"
)

// adjudicate.go — selective-abort (component 7). A deviator named by enough
// distinct accusers is excluded; the committee continues with the qualified
// survivors. Adjudication is DETERMINISTIC: every honest party that processes
// the same verified-complaint set computes the same disqualified set and the
// same survivor list, so the chain reaches one verdict.

// DisqualificationThreshold returns the minimum number of distinct, validly
// signed accusers required to disqualify a dealer. Default: t-1. Rationale: a
// single Byzantine validator can emit one false complaint to slow the protocol,
// but to disqualify an HONEST dealer an adversary needs t-1 collaborators —
// exactly one beyond the static-corruption budget of t-1, so an honest dealer
// is never excluded.
func DisqualificationThreshold(t int) int {
	if t <= 1 {
		return 1
	}
	return t - 1
}

// ComputeDisqualified returns the set of dealers (Accused) that meet the
// disqualification threshold over a slice of ALREADY-VERIFIED complaints.
// "Verified" means each complaint passed Complaint.Verify (form + signature)
// AND, where applicable, its cryptographic claim was re-checked by the vss
// layer; this function does not re-verify — it only counts.
//
// Complaints are deduplicated by (accused, accuser): a single accuser counts at
// most once against a given dealer, so a lone party cannot manufacture a quorum
// by repeating itself.
func ComputeDisqualified(complaints []*Complaint, threshold int) map[channel.NodeID]struct{} {
	need := DisqualificationThreshold(threshold)
	seen := make(map[[2]channel.NodeID]bool)
	count := make(map[channel.NodeID]int)
	for _, c := range complaints {
		key := [2]channel.NodeID{c.Accused, c.Accuser}
		if seen[key] {
			continue
		}
		seen[key] = true
		count[c.Accused]++
	}
	out := make(map[channel.NodeID]struct{})
	for accused, n := range count {
		if n >= need {
			out[accused] = struct{}{}
		}
	}
	return out
}

// FilterQualified removes the disqualified dealers from the committee and
// returns the survivor list in canonical (byte-sorted) order. Returns
// ErrInsufficientQuorum if fewer than threshold survivors remain — in which
// case the DKG aborts, the activation cert binds the abort transcript, and the
// chain stays at the previous era.
func FilterQualified(committee []channel.NodeID, disqualified map[channel.NodeID]struct{}, threshold int) ([]channel.NodeID, error) {
	out := make([]channel.NodeID, 0, len(committee))
	for _, id := range committee {
		if _, dq := disqualified[id]; dq {
			continue
		}
		out = append(out, id)
	}
	if len(out) < threshold {
		return nil, ErrInsufficientQuorum
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i][:], out[j][:]) < 0
	})
	return out, nil
}
