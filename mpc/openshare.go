// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

// openshare.go — closer (c): identifiable abort at a reconstruction.
//
// A reconstruction (open) reveals one degree-(T-1) sharing at X=0 by collecting
// the parties' opening shares. A malicious party can broadcast a share different
// from the one it should reveal, biasing the result. We close this with
// commit-then-open BINDING, NOT Reed-Solomon decoding:
//
//   1. before any share is revealed, every party broadcasts a SIGNED commitment
//      to its opening share (a cSHAKE256 hash commit; component 8, applied to
//      the open). This fixes each share before the adversary sees the others.
//   2. parties then reveal (share, nonce). A reveal whose (share, nonce) does
//      NOT open the party's committed digest is an equivocation — the party is
//      named directly by the binding (OpeningFault → ReasonBadOpening). No
//      honest-majority decoding is invoked, so the unsoundness of RS correction
//      at N = 2T-1 against T-1 corruptions never bites.
//   3. the commitment-bound shares must then form a degree-(T-1) codeword
//      (CheckDegree). If they do, the reconstruction is the unique honest value.
//      If they do NOT — a party committed (from the start) to a share off the
//      honest polynomial — the corruption was introduced UPSTREAM at deal time;
//      that traces to the committed re-share whose degree check fails (closer a,
//      committed.go). So every open deviation is either a direct OpeningFault or
//      reduces to a ReshareFault; neither leaks nor forges.

// CommitOpening commits a party to a single opening share (commit-then-open
// binding), in a cSHAKE domain disjoint from re-share and bit commitments.
func CommitOpening(share Elem, nonce []byte) []byte {
	return commitBytes(csOpenCommit, []Elem{share}, nonce)
}

// OpeningReveal is one party's revealed opening share, its nonce, the earlier
// signed commitment, and the party's signature over that commitment.
type OpeningReveal struct {
	Party  int
	Share  Elem
	Nonce  []byte
	Commit []byte // the party's earlier broadcast commitment (binding)
	Sig    []byte // the party's signature over Commit (verified at the bridge)
}

// OpeningFault carries publicly-re-checkable evidence that a party equivocated
// at an open: it signed Commit, then revealed (Share, Nonce) that does NOT open
// it. The blame bridge mints a ReasonBadOpening complaint.
type OpeningFault struct {
	Party  int
	Share  Elem
	Nonce  []byte
	Commit []byte
	Sig    []byte
}

// DealOpening builds a party's commit-then-open binding for one reconstruction:
// the share, a fresh nonce, and the binding commitment to broadcast first.
func DealOpening(share Elem, rng interface{ Read([]byte) (int, error) }) (*OpeningReveal, error) {
	nonce, err := NewNonce(rng)
	if err != nil {
		return nil, err
	}
	return &OpeningReveal{Share: share, Nonce: nonce, Commit: CommitOpening(share, nonce)}, nil
}

// IdentifiableOpen reconstructs a value at X=0 from N revealed opening shares
// and names any equivocator. For each reveal it checks the (share, nonce) opens
// the party's committed digest; a mismatch is an OpeningFault (the share is
// unbound and untrusted). If no equivocation occurred AND the N bound shares
// form a degree-(threshold-1) codeword, the returned value is the unique honest
// reconstruction and clean is true. Otherwise clean is false and value is unsafe
// to use — the caller aborts, blames (or, for a non-codeword with no
// equivocation, re-checks the upstream committed re-shares), and retries.
//
// reveals must be parallel to evalPoints (reveals[i] is the party at
// evalPoints[i]). Order is by party index; Party fields are informational.
func (f *Field) IdentifiableOpen(reveals []*OpeningReveal, evalPoints []Elem, threshold int) (value Elem, faults []*OpeningFault, clean bool, err error) {
	n := len(evalPoints)
	if len(reveals) != n {
		return 0, nil, false, ErrShape
	}
	if threshold < 1 || n < threshold {
		return 0, nil, false, ErrInvalidThreshold
	}
	shares := make([]Elem, n)
	for i, r := range reveals {
		if r == nil {
			return 0, nil, false, ErrShape
		}
		if !equalConst(r.Commit, CommitOpening(r.Share, r.Nonce)) {
			faults = append(faults, &OpeningFault{
				Party: r.Party, Share: r.Share, Nonce: r.Nonce, Commit: r.Commit, Sig: r.Sig,
			})
		}
		shares[i] = r.Share
	}
	if len(faults) > 0 {
		return 0, faults, false, nil
	}
	if !f.CheckDegree(evalPoints, shares, threshold) {
		// No equivocation, but the bound shares are not a codeword: an upstream
		// committed re-share was malformed (trace via closer a). Not clean.
		return 0, nil, false, nil
	}
	v, rerr := f.Reconstruct(evalPoints[:threshold], shares[:threshold])
	if rerr != nil {
		return 0, nil, false, rerr
	}
	return v, nil, true, nil
}
