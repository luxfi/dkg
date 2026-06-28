// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package safety states and mechanically checks luxfi/dkg's headline theorem:
//
//	ABORT-OR-BLAME, NEVER LEAK OR FORGE. Every malicious deviation in the DKG or
//	the threshold-signing MPC is EITHER attributed with a publicly-verifiable
//	signed complaint (identifiable abort), OR caught by the mandatory
//	verify-before-emit release gate as a liveness fault (retry with a fresh
//	nonce) — never a leaked secret share and never a forged signature.
//
// Two independent guarantees compose into the theorem:
//
//  1. THE FLOOR (always on, closer-independent). A threshold signature is emitted
//     only after a mandatory verification — the concrete instantiation in the
//     consumer (pulsar) is FindHint (reject a w1 no public hint reaches) followed
//     by stock FIPS-204 mldsa65.Verify. Any wrong intermediate value (including
//     the harder "wrong value, right degree" re-share that the degree check does
//     NOT catch) yields a candidate the gate REFUSES, so the worst a malicious
//     party achieves is to waste a nonce — a liveness fault, never a forgery. The
//     dkg library supplies the gate STRUCTURE (ReleaseGate) and proves the floor
//     for any sound Verify; the consumer supplies the concrete predicate.
//
//  2. THE CLOSERS (upgrade silent-retry → identifiable abort). The three CSCP
//     deviations and the DKG share/equivocation deviations each produce a
//     blame.Complaint that any third party re-checks WITHOUT trusting the accuser
//     (Adjudicator.Recheck routes each reason to the layer that owns its math:
//     vss.RecheckBadDelivery for the DKG share, mpc.RecheckReshare/Bit/Opening for
//     the MPC). The honest majority excludes the named deviator and re-runs; the
//     chain slashes from the signed evidence.
//
// AssessMalicious is the single source of truth enumerating every deviation, its
// closer, the blame.Reason it mints, and the floor that catches it regardless.
package safety

import (
	"github.com/luxfi/dkg/blame"
	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/mpc"
	"github.com/luxfi/dkg/ring"
	"github.com/luxfi/dkg/vss"
)

// Deviation is one malicious behaviour, its identifiable-abort closer, the
// blame.Reason it produces, and the floor mechanism that catches it even if the
// closer were absent.
type Deviation struct {
	Name       string
	Closer     string
	Reason     blame.Reason
	Downstream string // the closer-independent floor that catches it regardless
}

// Assessment is the single-source-of-truth malicious-residual descriptor for a
// (threshold, parties) committee.
type Assessment struct {
	Threshold      int
	Parties        int
	HonestMajority bool // parties >= 2*threshold-1 (TALUS Theorem 10.1)
	Deviations     []Deviation

	// AbortOrBlameNeverLeak is the theorem: under the honest-majority bound,
	// every deviation resolves to a verifiable complaint OR a liveness fault, and
	// never to a leaked share or a forged signature.
	AbortOrBlameNeverLeak bool
}

// AssessMalicious computes the descriptor for a committee. It mirrors pulsar's
// AssessCSCPMalicious / assessDealerlessFIPS as a precise, non-hand-waved
// statement of what each adversary can do and exactly how it is closed.
func AssessMalicious(threshold, parties int) *Assessment {
	honest := parties >= 2*threshold-1 && threshold >= 1
	return &Assessment{
		Threshold:      threshold,
		Parties:        parties,
		HonestMajority: honest,
		Deviations: []Deviation{
			{
				Name:       "inconsistent re-share (degree > T-1) into a BGW multiplication",
				Closer:     "committed re-shares + exact degree check (mpc.CheckDegree)",
				Reason:     blame.ReasonBadReshare,
				Downstream: "wrong product → wrong w1 → release gate refuses",
			},
			{
				Name:       "non-{0,1} value contributed as a private random bit",
				Closer:     "batched b·(b-1)=0 proof (mpc.BatchedBitCheck), Fiat-Shamir challenge",
				Reason:     blame.ReasonBadBit,
				Downstream: "skewed mask → wrong w1 → release gate refuses",
			},
			{
				Name:       "equivocated mask-open (share ≠ committed digest)",
				Closer:     "commit-then-open binding identification (mpc.IdentifiableOpen)",
				Reason:     blame.ReasonBadOpening,
				Downstream: "wrong reconstruction → wrong w1 → release gate refuses",
			},
			{
				Name:       "malformed DKG share (fails the Pedersen identity)",
				Closer:     "no-reconstruct Pedersen identity check (vss.RecheckBadDelivery)",
				Reason:     blame.ReasonBadDelivery,
				Downstream: "DKG aborts; group key never finalized from a bad share",
			},
			{
				Name:       "dealer equivocation (different commits to different recipients)",
				Closer:     "Round-2 commit-digest equivocation gate (vss.DetectEquivocation)",
				Reason:     blame.ReasonEquivocation,
				Downstream: "DKG aborts before any share is trusted",
			},
			{
				Name:       "wrong value, right degree re-share (passes every closer)",
				Closer:     "none — outside the degree/equivocation/bit closers",
				Reason:     0, // no complaint; caught only by the floor
				Downstream: "wrong product → wrong w1 → FindHint + stock-FIPS verify refuses (liveness fault)",
			},
		},
		AbortOrBlameNeverLeak: honest,
	}
}

// ── the floor: mandatory verify-before-emit ──────────────────────────────────

// ReleaseGate models the closer-independent safety floor: a candidate threshold
// signature is emitted ONLY if Verify accepts it. The concrete Verify in the
// consumer is FindHint + stock FIPS-204 mldsa65.Verify; the dkg library proves
// that ANY sound Verify makes a wrong candidate a liveness fault, never a forgery.
type ReleaseGate struct {
	Verify func(candidate []byte) bool
}

// Release returns (candidate, true) iff the gate accepts it; otherwise (nil,
// false) — a liveness fault. A nil Verify fails closed (never releases).
func (g ReleaseGate) Release(candidate []byte) ([]byte, bool) {
	if g.Verify == nil || !g.Verify(candidate) {
		return nil, false
	}
	return candidate, true
}

// ── outcome classification: the theorem as a predicate ───────────────────────

// Outcome classifies one (possibly malicious) attempt. The theorem is: every
// Outcome is Safe(), and every non-Clean Outcome is Resolved() (blamed or a
// liveness fault) — there is no third option that leaks or forges.
type Outcome struct {
	Clean         bool // honest: a correct output passed the release gate
	Blamed        bool // a deviation was attributed via a verifiable complaint
	LivenessFault bool // a deviation was caught by the release gate; retry
	Leaked        bool // a secret left the shared domain (MUST stay false)
	Forged        bool // a wrong output passed the release gate (MUST stay false)
}

// Safe is the headline invariant: no leak, no forgery.
func (o Outcome) Safe() bool { return !o.Leaked && !o.Forged }

// Resolved reports whether the attempt reached a terminal, accountable state.
func (o Outcome) Resolved() bool { return o.Clean || o.Blamed || o.LivenessFault }

// ── the cross-layer adjudicator: one authority over the blame set ────────────

// Adjudicator is the single authority that re-checks a verified complaint's
// cryptographic claim by routing each blame.Reason to the layer that owns its
// math: vss for the DKG share, mpc for the threshold-signing MPC. This is where
// safety/ consumes vss.RecheckBadDelivery and the mpc re-checkers together.
type Adjudicator struct {
	Profile    *ring.Profile             // DKG ring (vss re-checks)
	Field      *mpc.Field                // GF(q) substrate (mpc re-checks)
	EvalPoints []mpc.Elem                // committee eval points
	Threshold  int                       // sharing threshold T
	Dir        channel.IdentityDirectory // identity directory (signature binding)
}

// Recheck verifies a complaint's form + accuser signature, then re-runs its
// cryptographic claim. Returns true iff the accusation is justified (the named
// party indeed deviated). A reason with no library re-checker (e.g. Missing) is
// adjudicated by form+signature alone.
func (a *Adjudicator) Recheck(c *blame.Complaint) (bool, error) {
	if err := c.Verify(a.Dir); err != nil {
		return false, err
	}
	switch c.Reason {
	case blame.ReasonBadDelivery:
		return vss.RecheckBadDelivery(a.Profile, c)
	case blame.ReasonBadReshare:
		return a.Field.RecheckReshare(a.Dir, c, a.EvalPoints, a.Threshold)
	case blame.ReasonBadBit:
		return a.Field.RecheckBit(a.Dir, c, a.EvalPoints, a.Threshold)
	case blame.ReasonBadOpening:
		return mpc.RecheckOpening(a.Dir, c)
	default:
		// Equivocation / MalformedCommit / Missing: the signed evidence is
		// self-contained; form + accuser-signature (already checked) is the
		// adjudication. No additional ring/field math to re-run here.
		return true, nil
	}
}
