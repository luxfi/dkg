// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package transcript

import (
	"bytes"
	"testing"
)

// TestEncoders pins the SP 800-185 §2.3 encoders to the standard's worked
// values (left_encode(0)=0100, right_encode(0)=0001), and checks encode_string
// framing length.
func TestEncoders(t *testing.T) {
	if got := leftEncode(0); !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Fatalf("left_encode(0) = %x, want 0100", got)
	}
	if got := rightEncode(0); !bytes.Equal(got, []byte{0x00, 0x01}) {
		t.Fatalf("right_encode(0) = %x, want 0001", got)
	}
	// left_encode(8*1) for a 1-byte string: byte-length 1 → bit length 8.
	if got := leftEncode(8); !bytes.Equal(got, []byte{0x01, 0x08}) {
		t.Fatalf("left_encode(8) = %x, want 0108", got)
	}
	// bytepad pads to a multiple of w.
	if got := bytepad([]byte{0xAA}, 8); len(got)%8 != 0 {
		t.Fatalf("bytepad length %d not multiple of 8", len(got))
	}
}

// TestTranscriptDeterministic checks two transcripts with identical appends
// produce identical hashes, and that order / label / data changes all diverge.
func TestTranscriptDeterministic(t *testing.T) {
	build := func() *Transcript {
		return New().
			Append("round", []byte("r1")).
			AppendU32("n", 5).
			AppendHash("commit", [32]byte{1, 2, 3})
	}
	if build().Hash() != build().Hash() {
		t.Fatal("identical transcripts must hash equally")
	}

	base := build().Hash()

	// Different data.
	diff1 := New().Append("round", []byte("r2")).AppendU32("n", 5).AppendHash("commit", [32]byte{1, 2, 3})
	if diff1.Hash() == base {
		t.Fatal("different data must diverge")
	}
	// Different order.
	diff2 := New().AppendU32("n", 5).Append("round", []byte("r1")).AppendHash("commit", [32]byte{1, 2, 3})
	if diff2.Hash() == base {
		t.Fatal("different order must diverge")
	}
	// Different label.
	diff3 := New().Append("ROUND", []byte("r1")).AppendU32("n", 5).AppendHash("commit", [32]byte{1, 2, 3})
	if diff3.Hash() == base {
		t.Fatal("different label must diverge")
	}
}

// TestFramingNoBoundaryConfusion is the load-bearing property: a naive
// concatenation transcript collides on Append("a","bc") vs Append("ab","c");
// the TupleHash framing here must NOT.
func TestFramingNoBoundaryConfusion(t *testing.T) {
	h1 := New().Append("a", []byte("bc")).Hash()
	h2 := New().Append("ab", []byte("c")).Hash()
	if h1 == h2 {
		t.Fatal("boundary confusion: framing failed to disambiguate label/data split")
	}
	// Splitting one append into two must also diverge from one combined.
	h3 := New().Append("x", []byte("12")).Hash()
	h4 := New().Append("x", []byte("1")).Append("", []byte("2")).Hash()
	if h3 == h4 {
		t.Fatal("entry-count framing failed to disambiguate")
	}
}

// TestDomainSeparation checks that the same payload under two customization
// tags produces different digests.
func TestDomainSeparation(t *testing.T) {
	payload := []byte("same-bytes")
	a := CommitDigest("TAG-A", payload)
	b := CommitDigest("TAG-B", payload)
	if a == b {
		t.Fatal("customization tag must separate domains")
	}
	// FuncName separation: a plain SHAKE (empty N) must differ from our domain.
	plain := CShake256(payload, 32, "", "TAG-A")
	domain := CShake256(payload, 32, FuncName, "TAG-A")
	if bytes.Equal(plain, domain) {
		t.Fatal("function-name N must separate the luxfi/dkg domain from plain cSHAKE")
	}
}

// TestKMAC256_KeyMatters checks KMAC256 depends on the key (a MAC, not a hash).
func TestKMAC256_KeyMatters(t *testing.T) {
	msg := []byte("authenticate me")
	a := KMAC256([]byte("key-1"), msg, 32, "T")
	b := KMAC256([]byte("key-2"), msg, 32, "T")
	if bytes.Equal(a, b) {
		t.Fatal("KMAC256 must depend on the key")
	}
	if len(a) != 32 {
		t.Fatalf("KMAC256 outLen = %d, want 32", len(a))
	}
}

// TestFork checks a forked transcript diverges independently from its parent.
func TestFork(t *testing.T) {
	base := New().Append("prefix", []byte("p"))
	f := base.Fork()
	base.Append("a", []byte("1"))
	f.Append("b", []byte("2"))
	if base.Hash() == f.Hash() {
		t.Fatal("forked transcripts must evolve independently")
	}
}
