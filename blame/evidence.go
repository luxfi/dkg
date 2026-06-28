// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package blame

import (
	"bytes"
	"encoding/binary"
)

// evidence.go — canonical TLV evidence: field = 4-byte BE length ‖ payload.
// Each Reason has a fixed field count; validateEvidence checks the count, the
// per-field minimum length, and a per-reason structural sanity rule. This is
// the third-party-checkable SHAPE of the evidence, independent of the ring
// math. Ported from the pulsar reference (pulsar/abort.go) generalized to the
// luxfi/dkg reason set.
//
// A blob valid for reason A will NOT validate under reason B because the field
// counts differ — so an attacker cannot relabel evidence to a cheaper-to-forge
// reason.

// Per-reason evidence field counts.
const (
	badDeliveryFields  = 3 // (share, blind, commits)
	equivocationFields = 4 // (commit1, commit2, sig1, sig2)
	malformedFields    = 1 // (commits)
	missingFields      = 0 // absence is the evidence

	// Phase-2 malicious-MPC reasons. The scalar math re-check is mpc's job; blame
	// only checks the field count + per-field minimum length (scheme-agnostic).
	badReshareFields = 4 // (commit, nonce, shares, dealerSig)
	badOpeningFields = 4 // (commit, share, nonce, partySig)
	badBitFields     = 4 // (commit, nonce, shares, partySig)
)

// Per-field minimum byte lengths (conservative, scheme-agnostic).
const (
	shareMin  = 8 // at least one coefficient
	blindMin  = 8
	commitMin = 8
	sigMin    = 64 // FIPS-204 minimum across schemes
	// digestMin is the byte length of a cSHAKE256 commitment digest / nonce as
	// used by the malicious-MPC reasons (32 bytes).
	digestMin = 32
)

// parseFields splits a TLV blob into its payloads. Returns ErrComplaintForm on
// a truncated length prefix or an overrun.
func parseFields(blob []byte) ([][]byte, error) {
	fields := make([][]byte, 0, 4)
	off := 0
	for off < len(blob) {
		if len(blob)-off < 4 {
			return nil, ErrComplaintForm
		}
		l := binary.BigEndian.Uint32(blob[off : off+4])
		off += 4
		if uint64(off)+uint64(l) > uint64(len(blob)) {
			return nil, ErrComplaintForm
		}
		fields = append(fields, blob[off:off+int(l)])
		off += int(l)
	}
	return fields, nil
}

// encodeFields builds a TLV blob from payloads.
func encodeFields(payloads ...[]byte) []byte {
	var buf bytes.Buffer
	var b4 [4]byte
	for _, p := range payloads {
		binary.BigEndian.PutUint32(b4[:], uint32(len(p)))
		buf.Write(b4[:])
		buf.Write(p)
	}
	return buf.Bytes()
}

// validateEvidence dispatches per-reason structural validation.
func validateEvidence(reason Reason, blob []byte) error {
	switch reason {
	case ReasonMissing:
		// Empty evidence is valid (and required) for a missing complaint.
		if len(blob) != 0 {
			return ErrComplaintForm
		}
		return nil
	case ReasonBadDelivery:
		f, err := parseFields(blob)
		if err != nil {
			return err
		}
		if len(f) != badDeliveryFields {
			return ErrEvidenceFields
		}
		if len(f[0]) < shareMin || len(f[1]) < blindMin || len(f[2]) < commitMin {
			return ErrComplaintNoEv
		}
		return nil
	case ReasonEquivocation:
		f, err := parseFields(blob)
		if err != nil {
			return err
		}
		if len(f) != equivocationFields {
			return ErrEvidenceFields
		}
		if len(f[0]) < commitMin || len(f[1]) < commitMin {
			return ErrComplaintNoEv
		}
		if len(f[2]) < sigMin || len(f[3]) < sigMin {
			return ErrComplaintNoEv
		}
		// The two commit broadcasts must actually differ — else no equivocation.
		if bytes.Equal(f[0], f[1]) {
			return ErrEvidenceDuplicate
		}
		return nil
	case ReasonMalformedCommit:
		f, err := parseFields(blob)
		if err != nil {
			return err
		}
		if len(f) != malformedFields {
			return ErrEvidenceFields
		}
		if len(f[0]) < commitMin {
			return ErrComplaintNoEv
		}
		return nil
	case ReasonBadReshare, ReasonBadBit:
		// (commit[32], nonce[32], shares, partySig). The shares field carries the
		// committed N-share vector (>= one 8-byte scalar); partySig is FIPS-204.
		f, err := parseFields(blob)
		if err != nil {
			return err
		}
		if len(f) != badReshareFields {
			return ErrEvidenceFields
		}
		if len(f[0]) < digestMin || len(f[1]) < digestMin {
			return ErrComplaintNoEv
		}
		if len(f[2]) < shareMin || len(f[3]) < sigMin {
			return ErrComplaintNoEv
		}
		return nil
	case ReasonBadOpening:
		// (commit[32], share, nonce[32], partySig). The commitment was signed by
		// the party; the revealed (share, nonce) does not open it.
		f, err := parseFields(blob)
		if err != nil {
			return err
		}
		if len(f) != badOpeningFields {
			return ErrEvidenceFields
		}
		if len(f[0]) < digestMin || len(f[2]) < digestMin {
			return ErrComplaintNoEv
		}
		if len(f[1]) < shareMin || len(f[3]) < sigMin {
			return ErrComplaintNoEv
		}
		return nil
	default:
		return ErrComplaintReason
	}
}

// BadDeliveryEvidence builds the TLV evidence for a ReasonBadDelivery complaint
// from pre-serialized share, blind, and commit bytes. The vss layer produces
// the serialized ring objects.
func BadDeliveryEvidence(shareBytes, blindBytes, commitsBytes []byte) []byte {
	return encodeFields(shareBytes, blindBytes, commitsBytes)
}

// EquivocationEvidence builds the TLV evidence for a ReasonEquivocation
// complaint: two disagreeing commit broadcasts and their two identity
// signatures.
func EquivocationEvidence(commit1, commit2, sig1, sig2 []byte) []byte {
	return encodeFields(commit1, commit2, sig1, sig2)
}

// MalformedCommitEvidence builds the TLV evidence for a ReasonMalformedCommit
// complaint from the malformed commit bytes.
func MalformedCommitEvidence(commitsBytes []byte) []byte {
	return encodeFields(commitsBytes)
}

// ParseBadDeliveryEvidence extracts (share, blind, commits) bytes from a
// ReasonBadDelivery evidence blob, for the vss re-checker.
func ParseBadDeliveryEvidence(blob []byte) (shareBytes, blindBytes, commitsBytes []byte, err error) {
	f, err := parseFields(blob)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(f) != badDeliveryFields {
		return nil, nil, nil, ErrEvidenceFields
	}
	return f[0], f[1], f[2], nil
}

// BadReshareEvidence builds the TLV evidence for a ReasonBadReshare complaint:
// the dealer's hash commitment, the opening nonce, the canonical N-share bytes,
// and the dealer's signature over the commitment. The mpc re-checker re-hashes
// the shares (binding) and runs the degree test.
func BadReshareEvidence(commit, nonce, shares, dealerSig []byte) []byte {
	return encodeFields(commit, nonce, shares, dealerSig)
}

// ParseBadReshareEvidence extracts (commit, nonce, shares, dealerSig) for the
// mpc re-checker. Shared by ReasonBadReshare and ReasonBadBit (same shape).
func ParseBadReshareEvidence(blob []byte) (commit, nonce, shares, dealerSig []byte, err error) {
	f, err := parseFields(blob)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(f) != badReshareFields {
		return nil, nil, nil, nil, ErrEvidenceFields
	}
	return f[0], f[1], f[2], f[3], nil
}

// BadBitEvidence builds the TLV evidence for a ReasonBadBit complaint: the
// party's commitment to its own bit-sharing, the nonce, the N-share bytes, and
// the party's signature. Same field shape as ReasonBadReshare.
func BadBitEvidence(commit, nonce, shares, partySig []byte) []byte {
	return encodeFields(commit, nonce, shares, partySig)
}

// ParseBadBitEvidence is ParseBadReshareEvidence under the ReasonBadBit name.
func ParseBadBitEvidence(blob []byte) (commit, nonce, shares, partySig []byte, err error) {
	return ParseBadReshareEvidence(blob)
}

// BadOpeningEvidence builds the TLV evidence for a ReasonBadOpening complaint:
// the party's signed commitment digest, the revealed share, the revealed nonce,
// and the party's signature over the commitment. The mpc re-checker confirms the
// revealed (share, nonce) does NOT open the committed digest.
func BadOpeningEvidence(commit, share, nonce, partySig []byte) []byte {
	return encodeFields(commit, share, nonce, partySig)
}

// ParseBadOpeningEvidence extracts (commit, share, nonce, partySig).
func ParseBadOpeningEvidence(blob []byte) (commit, share, nonce, partySig []byte, err error) {
	f, err := parseFields(blob)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(f) != badOpeningFields {
		return nil, nil, nil, nil, ErrEvidenceFields
	}
	return f[0], f[1], f[2], f[3], nil
}
