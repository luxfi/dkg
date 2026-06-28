// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package channel is the authenticated-message layer for luxfi/dkg: long-term
// party identity (ML-KEM-768 + ML-DSA-65), per-recipient sealed envelopes, and
// commit-then-reveal. It is the "who said what, and only the right party can
// read it" concern, kept orthogonal to the ring algebra (ring/) and the
// protocol logic (vss/).
//
// Two security fixes over the pulsar v0.1 channel are structural here:
//
//  1. SHARE-ONLY ENVELOPES. The v0.1 sealed envelope carried BOTH the Shamir
//     share AND the full dealer contribution c_i, so every committee member
//     who opened an envelope learned a full contribution — which, summed, is
//     the master secret. That defeated the whole point of secret sharing. Here
//     Seal carries ONLY the per-recipient share; there is no contribution
//     field, structurally (DESIGN.md channel/, "FIX the v0.1 leak").
//
//  2. COMMIT-THEN-REVEAL (component 8). commit.go forces every party to commit
//     to its contribution before seeing anyone else's, removing the last-mover
//     advantage where a rushing adversary biases the joint key by choosing its
//     contribution after observing the others.
package channel

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// NodeID is a party's 32-byte identifier (a chain validator NodeID / hash of
// the long-term identity key). It names parties in envelopes, sessions, and
// complaints.
type NodeID [32]byte

// Errors returned by identity / envelope operations.
var (
	ErrShortRand          = errors.New("dkg/channel: entropy source returned too few bytes")
	ErrIdentityKeyMissing = errors.New("dkg/channel: identity key missing")
	ErrIdentityCorrupted  = errors.New("dkg/channel: identity key bytes invalid")
	ErrPeerKEMPub         = errors.New("dkg/channel: peer KEM public key invalid")
	ErrPeerDSAPub         = errors.New("dkg/channel: peer ML-DSA public key invalid")
	ErrEnvelopeCiphertext = errors.New("dkg/channel: KEM ciphertext wrong size or invalid")
	ErrEnvelopeAuthBad    = errors.New("dkg/channel: envelope authentication tag invalid")
	ErrEnvelopeShareLen   = errors.New("dkg/channel: sealed share length mismatch")
)

// IdentityPublicKey is a party's publishable long-term identity: the
// ML-KEM-768 encapsulation key (envelope reception) and the ML-DSA-65
// verification key (authenticating broadcasts and complaints). Both are
// byte-packed per FIPS 203 / FIPS 204, so the struct is wire-safe to publish
// in a chain validator record.
type IdentityPublicKey struct {
	KEMPub   []byte // ML-KEM-768 public key (1184 bytes)
	MLDSAPub []byte // ML-DSA-65 public key (1952 bytes)
}

// IdentityKey is a party's long-term keypair. Publish only PublicKey(); keep
// the secret halves in HSM/KMS.
type IdentityKey struct {
	KEMPub    []byte
	KEMPriv   []byte
	MLDSAPub  []byte
	MLDSAPriv []byte
}

// PublicKey returns the publishable half of an IdentityKey.
func (k *IdentityKey) PublicKey() *IdentityPublicKey {
	if k == nil {
		return nil
	}
	return &IdentityPublicKey{
		KEMPub:   append([]byte{}, k.KEMPub...),
		MLDSAPub: append([]byte{}, k.MLDSAPub...),
	}
}

// GenerateIdentity produces a fresh long-term identity keypair from rng. Pass a
// deterministic reader for KAT reproducibility; rng must not be nil.
func GenerateIdentity(rng io.Reader) (*IdentityKey, error) {
	if rng == nil {
		return nil, ErrShortRand
	}
	var kemSeed [mlkem768.KeySeedSize]byte
	if _, err := io.ReadFull(rng, kemSeed[:]); err != nil {
		return nil, ErrShortRand
	}
	kemPub, kemPriv := mlkem768.NewKeyFromSeed(kemSeed[:])
	kpubB, err := kemPub.MarshalBinary()
	if err != nil {
		return nil, ErrIdentityCorrupted
	}
	kpriB, err := kemPriv.MarshalBinary()
	if err != nil {
		return nil, ErrIdentityCorrupted
	}
	var dsaSeed [32]byte
	if _, err := io.ReadFull(rng, dsaSeed[:]); err != nil {
		return nil, ErrShortRand
	}
	dpub, dpriv := mldsa65.NewKeyFromSeed(&dsaSeed)
	var dpubB [mldsa65.PublicKeySize]byte
	dpub.Pack(&dpubB)
	var dprivB [mldsa65.PrivateKeySize]byte
	dpriv.Pack(&dprivB)
	return &IdentityKey{
		KEMPub:    kpubB,
		KEMPriv:   kpriB,
		MLDSAPub:  append([]byte{}, dpubB[:]...),
		MLDSAPriv: append([]byte{}, dprivB[:]...),
	}, nil
}

// IdentityDirectory maps NodeID to the published IdentityPublicKey. The DKG
// looks up peer identity keys by NodeID without re-passing them on every call.
type IdentityDirectory map[NodeID]*IdentityPublicKey

// NewIdentityDirectory copies entries into a directory, rejecting nil keys.
func NewIdentityDirectory(entries map[NodeID]*IdentityPublicKey) (IdentityDirectory, error) {
	out := make(IdentityDirectory, len(entries))
	for id, ipk := range entries {
		if ipk == nil {
			return nil, ErrIdentityKeyMissing
		}
		out[id] = &IdentityPublicKey{
			KEMPub:   append([]byte{}, ipk.KEMPub...),
			MLDSAPub: append([]byte{}, ipk.MLDSAPub...),
		}
	}
	return out, nil
}

// Get returns the identity public key for id, or nil if absent.
func (d IdentityDirectory) Get(id NodeID) *IdentityPublicKey { return d[id] }

// nodeIDLess reports whether a < b in byte-lexicographic order. Used to derive
// canonical, direction-independent orderings (session keys, pair tags).
func nodeIDLess(a, b NodeID) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// ctEqual reports byte-equality of a and b in constant time.
func ctEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
