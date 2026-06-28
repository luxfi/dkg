// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package channel

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func mustIdentity(t *testing.T) *IdentityKey {
	t.Helper()
	id, err := GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

// TestEnvelope_RoundTrip checks a sealed share opens to the same bytes.
func TestEnvelope_RoundTrip(t *testing.T) {
	dealer := NodeID{1}
	recipient := NodeID{2}
	ctx := [32]byte{9, 9, 9}
	id := mustIdentity(t)
	share := []byte("this-is-a-128-byte-shamir-share-............................................................................................")

	env, err := Seal(dealer, recipient, ctx, share, id.KEMPub, nil, rand.Reader)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(dealer, recipient, ctx, env, len(share), id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, share) {
		t.Fatal("opened share mismatch")
	}
}

// TestEnvelope_ShareOnly is the v0.1-leak regression. The sealed payload MUST
// be exactly len(share) + 32-byte tag — NOT share + 32-byte contribution + tag.
// If a future change re-introduces a contribution field, this length check
// fails. This is the structural proof that an opener learns ONLY the share.
func TestEnvelope_ShareOnly(t *testing.T) {
	id := mustIdentity(t)
	for _, shareLen := range []int{64, 128} {
		share := bytes.Repeat([]byte{0x5A}, shareLen)
		env, err := Seal(NodeID{1}, NodeID{2}, [32]byte{}, share, id.KEMPub, nil, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		want := shareLen + envAuthTagSize // share ‖ tag, nothing else
		if len(env.Sealed) != want {
			t.Fatalf("shareLen=%d: sealed payload = %d bytes, want %d (share ‖ tag). "+
				"A larger payload means a contribution field leaked back in.",
				shareLen, len(env.Sealed), want)
		}
	}
}

// TestEnvelope_Tamper checks a flipped ciphertext byte fails the auth tag.
func TestEnvelope_Tamper(t *testing.T) {
	id := mustIdentity(t)
	share := bytes.Repeat([]byte{7}, 64)
	env, _ := Seal(NodeID{1}, NodeID{2}, [32]byte{}, share, id.KEMPub, nil, rand.Reader)
	env.Sealed[3] ^= 0xFF
	if _, err := Open(NodeID{1}, NodeID{2}, [32]byte{}, env, 64, id); err != ErrEnvelopeAuthBad {
		t.Fatalf("tampered envelope: err = %v, want ErrEnvelopeAuthBad", err)
	}
}

// TestEnvelope_ContextBinding checks an envelope sealed under one context does
// not open under another (relayed-envelope rejection).
func TestEnvelope_ContextBinding(t *testing.T) {
	id := mustIdentity(t)
	share := bytes.Repeat([]byte{7}, 64)
	env, _ := Seal(NodeID{1}, NodeID{2}, [32]byte{0xAA}, share, id.KEMPub, nil, rand.Reader)
	if _, err := Open(NodeID{1}, NodeID{2}, [32]byte{0xBB}, env, 64, id); err != ErrEnvelopeAuthBad {
		t.Fatalf("wrong context: err = %v, want ErrEnvelopeAuthBad", err)
	}
	// Wrong dealer/recipient binding also fails.
	if _, err := Open(NodeID{9}, NodeID{2}, [32]byte{0xAA}, env, 64, id); err != ErrEnvelopeAuthBad {
		t.Fatalf("wrong dealer: err = %v, want ErrEnvelopeAuthBad", err)
	}
}

// TestEnvelope_DeterministicEncap checks a fixed encapSeed yields byte-stable
// envelopes (KAT reproducibility).
func TestEnvelope_DeterministicEncap(t *testing.T) {
	id := mustIdentity(t)
	share := bytes.Repeat([]byte{3}, 64)
	seed := make([]byte, mlkem768.EncapsulationSeedSize)
	seed[0] = 0x42
	e1, err := Seal(NodeID{1}, NodeID{2}, [32]byte{}, share, id.KEMPub, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := Seal(NodeID{1}, NodeID{2}, [32]byte{}, share, id.KEMPub, seed, nil)
	if !bytes.Equal(e1.KEMCiphertext, e2.KEMCiphertext) || !bytes.Equal(e1.Sealed, e2.Sealed) {
		t.Fatal("deterministic encapSeed must yield byte-stable envelopes")
	}
}

// TestSignVerify checks ML-DSA-65 sign/verify with context separation.
func TestSignVerify(t *testing.T) {
	id := mustIdentity(t)
	msg := []byte("commit-digest-broadcast")
	sig, err := Sign(id, CtxBroadcast, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(id.PublicKey(), CtxBroadcast, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	// Wrong context must reject (cross-purpose reuse blocked).
	if Verify(id.PublicKey(), CtxComplaint, msg, sig) {
		t.Fatal("signature verified under wrong context")
	}
	// Tampered message must reject.
	if Verify(id.PublicKey(), CtxBroadcast, []byte("other"), sig) {
		t.Fatal("signature verified over wrong message")
	}
}

// TestCommitReveal checks commit-then-reveal binding and hiding properties.
func TestCommitReveal(t *testing.T) {
	contribution := []byte("party-i contribution c_i")
	nonce, err := NewNonce(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := Commit(contribution, nonce)

	// Correct opening verifies.
	if !VerifyOpening(c, Opening{Payload: contribution, Nonce: nonce}) {
		t.Fatal("valid opening rejected")
	}
	// Binding: a different payload under the same nonce must not open.
	if VerifyOpening(c, Opening{Payload: []byte("different c_i"), Nonce: nonce}) {
		t.Fatal("binding broken: wrong payload opened")
	}
	// Binding: a different nonce must not open.
	var other [32]byte
	other[0] = nonce[0] ^ 1
	if VerifyOpening(c, Opening{Payload: contribution, Nonce: other}) {
		t.Fatal("binding broken: wrong nonce opened")
	}
	// Hiding: the commitment of a different nonce differs (no leakage of payload
	// structure across nonces).
	c2 := Commit(contribution, other)
	if c == c2 {
		t.Fatal("hiding: same payload under different nonces collided")
	}
}

// TestDirectoryVerifier checks the blame-layer adapter verifies complaint
// signatures via the identity directory.
func TestDirectoryVerifier(t *testing.T) {
	id := mustIdentity(t)
	accuser := NodeID{7}
	dir, err := NewIdentityDirectory(map[NodeID]*IdentityPublicKey{accuser: id.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	v := DirectoryVerifier{Dir: dir}
	tb := []byte("complaint transcript bytes")
	sig, _ := Sign(id, CtxComplaint, tb)
	if !v.VerifyComplaintSignature(accuser, tb, sig) {
		t.Fatal("valid complaint signature rejected")
	}
	if v.VerifyComplaintSignature(NodeID{99}, tb, sig) {
		t.Fatal("unknown accuser must reject")
	}
}
