// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transcript

// transcript.go — the canonical, append-only MPC transcript.
//
// A Transcript is an ordered list of labelled byte-strings. Every honest party
// that appends the same (label, data) entries in the same order produces a
// byte-identical pre-image and therefore a byte-identical TranscriptHash. The
// hash is what a chain commits to in order to ratify a DKG/reshare era, and is
// what slashing evidence binds against (a stale transcript hash is rejected).
//
// Unambiguous framing. The pre-image uses SP 800-185 TupleHash256 encoding:
// the entry count is left_encoded, then every entry is encode_string'd (its
// bit-length is prepended). Two different (label, data) sequences therefore
// can never collide on the byte pre-image regardless of how lengths line up —
// this closes the classic length-extension / boundary-confusion attack on
// naive concatenation transcripts.

import (
	"encoding/binary"
)

// Domain function-name and the default customization tag for luxfi/dkg
// transcripts. Consumers that must stay byte-compatible with a legacy
// pulsar/corona transcript construct with NewWithDomain and pass their own
// (funcName, customization).
const (
	// FuncName is the SP 800-185 cSHAKE function-name N pinned for luxfi/dkg.
	// A non-empty N means feeding luxfi/dkg transcript bytes into a vanilla
	// SHAKE engine deterministically mismatches.
	FuncName = "LuxDKG"
	// TagTranscript is the default customization tag for a session transcript.
	TagTranscript = "LUX-DKG-TRANSCRIPT-V1"
)

// Transcript is an append-only, byte-stable MPC record.
type Transcript struct {
	funcName string
	tag      string
	parts    [][]byte
}

// New starts an empty transcript under the default luxfi/dkg domain.
func New() *Transcript { return NewWithDomain(FuncName, TagTranscript) }

// NewWithDomain starts an empty transcript under a caller-supplied SP 800-185
// (funcName, customization) domain. Use this to bind a session-specific tag or
// to reproduce a legacy consumer's exact wire bytes.
func NewWithDomain(funcName, customization string) *Transcript {
	return &Transcript{funcName: funcName, tag: customization}
}

// Append records one labelled entry. The label is bound into the entry
// (label ‖ 0x1F ‖ data, then TupleHash-framed) so an entry under a different
// label is a distinct transcript position. Returns the receiver for chaining.
func (t *Transcript) Append(label string, data []byte) *Transcript {
	entry := make([]byte, 0, len(label)+1+len(data))
	entry = append(entry, label...)
	entry = append(entry, 0x1F) // unit-separator: label/data boundary marker.
	entry = append(entry, data...)
	t.parts = append(t.parts, entry)
	return t
}

// AppendU32 records a big-endian uint32 under a label.
func (t *Transcript) AppendU32(label string, v uint32) *Transcript {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return t.Append(label, b[:])
}

// AppendU64 records a big-endian uint64 under a label.
func (t *Transcript) AppendU64(label string, v uint64) *Transcript {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return t.Append(label, b[:])
}

// AppendHash records a 32-byte digest under a label (e.g. a per-party commit
// digest in the Round-1.5 equivocation gate).
func (t *Transcript) AppendHash(label string, h [32]byte) *Transcript {
	return t.Append(label, h[:])
}

// Len returns the number of entries recorded so far.
func (t *Transcript) Len() int { return len(t.parts) }

// preimage returns the TupleHash256-framed byte pre-image of the transcript:
// left_encode(count) ‖ encode_string(entry_0) ‖ … ‖ encode_string(entry_{n-1}).
func (t *Transcript) preimage() []byte {
	buf := make([]byte, 0, 64+len(t.parts)*48)
	buf = append(buf, leftEncode(uint64(len(t.parts)))...)
	for _, p := range t.parts {
		buf = append(buf, encodeString(p)...)
	}
	return buf
}

// Hash returns the 32-byte TranscriptHash: cSHAKE256(preimage, 32, funcName,
// tag). This is the value the chain commits to.
func (t *Transcript) Hash() [32]byte {
	out := CShake256(t.preimage(), 32, t.funcName, t.tag)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

// Hash48 returns the 48-byte TranscriptHash, matching FIPS-204's commitment
// width (CTildeSize) so the digest can double as a chain-pinning value without
// rehashing.
func (t *Transcript) Hash48() [48]byte {
	out := CShake256(t.preimage(), 48, t.funcName, t.tag)
	var ret [48]byte
	copy(ret[:], out)
	return ret
}

// Fork returns an independent copy of the transcript at its current state, so a
// caller can branch (e.g. commit the Round-1 prefix, then continue) without
// mutating the original.
func (t *Transcript) Fork() *Transcript {
	cp := &Transcript{funcName: t.funcName, tag: t.tag, parts: make([][]byte, len(t.parts))}
	for i, p := range t.parts {
		cp.parts[i] = append([]byte(nil), p...)
	}
	return cp
}

// CommitDigest is a standalone helper for the per-message commit digests used
// in the Round-1.5 equivocation gate (DESIGN component 5). It binds a tag and
// the SP 800-185 customization so two suites can never collide on the same
// payload. Equivalent to the corona/dkg2 CommitDigest under the luxfi/dkg
// domain.
func CommitDigest(tag string, payload []byte) [32]byte {
	out := CShake256(payload, 32, FuncName, tag)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}
