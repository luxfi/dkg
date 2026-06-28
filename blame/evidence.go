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
)

// Per-field minimum byte lengths (conservative, scheme-agnostic).
const (
	shareMin  = 8  // at least one coefficient
	blindMin  = 8
	commitMin = 8
	sigMin    = 64 // FIPS-204 minimum across schemes
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
