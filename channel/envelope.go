// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package channel

import (
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/luxfi/dkg/transcript"
)

// envelope.go — per-recipient sealed envelopes carrying ONLY a Shamir share.
//
// THE FIX. pulsar v0.1's sealEnvelope sealed (share ‖ FULL contribution c_i).
// Any committee member who opened an envelope learned a full dealer
// contribution; the sum of contributions is the master secret, so a single
// honest-but-curious member who collected the envelopes addressed to it across
// dealers learned every dealer's contribution and reconstructed the secret.
// Here the sealed plaintext is the SHARE AND NOTHING ELSE — there is no
// contribution field in Envelope, structurally. A member learns only f_i(j),
// its own evaluation point, exactly as Shamir secret sharing intends.

// SP 800-185 customization tags for envelope key / stream / auth derivation.
const (
	envKeyTag    = "LUX-DKG-ENVKEY-V1"
	envStreamTag = "LUX-DKG-ENVSTREAM-V1"
	envAuthTag   = "LUX-DKG-ENVAUTH-V1"
)

// envAuthTagSize is the trailing KMAC256 tag width inside the sealed payload.
const envAuthTagSize = 32

// Envelope is one party's sealed message to a single recipient. KEMCiphertext
// is the ML-KEM-768 encapsulation to the recipient's long-term KEM key; Sealed
// is the cSHAKE256-stream-encrypted (share ‖ auth-tag). The share width is
// recovered by the opener from the expected length.
type Envelope struct {
	KEMCiphertext []byte
	Sealed        []byte
}

// Seal encrypts shareWire to recipient under their long-term KEM public key,
// binding the (dealer, recipient, context) tuple. context is a 32-byte era /
// committee root that ties the envelope to one ceremony (a relayed envelope
// under a different context fails the auth tag).
//
// encapSeed, if non-nil, makes the ML-KEM encapsulation deterministic for KAT
// reproducibility; it must be exactly mlkem768.EncapsulationSeedSize bytes.
// Pass nil for a random encapsulation drawn from rng.
func Seal(
	dealer, recipient NodeID,
	context [32]byte,
	shareWire []byte,
	recipientKEMPub []byte,
	encapSeed []byte,
	rng io.Reader,
) (Envelope, error) {
	if len(recipientKEMPub) != mlkem768.PublicKeySize {
		return Envelope{}, ErrPeerKEMPub
	}
	if len(shareWire) == 0 {
		return Envelope{}, ErrEnvelopeShareLen
	}
	var pk mlkem768.PublicKey
	if err := pk.Unpack(recipientKEMPub); err != nil {
		return Envelope{}, ErrPeerKEMPub
	}
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	if encapSeed != nil {
		if len(encapSeed) != mlkem768.EncapsulationSeedSize {
			return Envelope{}, ErrEnvelopeCiphertext
		}
		pk.EncapsulateTo(ct, ss, encapSeed)
	} else {
		seed := make([]byte, mlkem768.EncapsulationSeedSize)
		if rng == nil {
			return Envelope{}, ErrShortRand
		}
		if _, err := io.ReadFull(rng, seed); err != nil {
			return Envelope{}, ErrShortRand
		}
		pk.EncapsulateTo(ct, ss, seed)
	}

	kEnv := deriveEnvelopeKey(ss, dealer, recipient, context)

	// Plaintext = share ‖ tag. NO contribution. This is the fix.
	sealedSize := len(shareWire) + envAuthTagSize
	plaintext := make([]byte, sealedSize)
	copy(plaintext[:len(shareWire)], shareWire)
	authInput := append(append(append([]byte{}, dealer[:]...), recipient[:]...), shareWire...)
	tag := transcript.KMAC256(kEnv[:], authInput, envAuthTagSize, envAuthTag)
	copy(plaintext[len(shareWire):], tag)

	stream := transcript.CShake256(kEnv[:], sealedSize, transcript.FuncName, envStreamTag)
	sealed := make([]byte, sealedSize)
	for i := range plaintext {
		sealed[i] = plaintext[i] ^ stream[i]
	}
	return Envelope{KEMCiphertext: ct, Sealed: sealed}, nil
}

// Open is the recipient-side counterpart to Seal. shareLen is the expected
// share width. Returns the recovered share, or ErrEnvelopeAuthBad if the tag
// fails (tampered envelope or wrong dealer/recipient/context binding).
func Open(
	dealer, recipient NodeID,
	context [32]byte,
	env Envelope,
	shareLen int,
	myIdentity *IdentityKey,
) ([]byte, error) {
	if myIdentity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if len(env.KEMCiphertext) != mlkem768.CiphertextSize {
		return nil, ErrEnvelopeCiphertext
	}
	if shareLen <= 0 {
		return nil, ErrEnvelopeShareLen
	}
	sealedSize := shareLen + envAuthTagSize
	if len(env.Sealed) != sealedSize {
		return nil, ErrEnvelopeShareLen
	}
	var sk mlkem768.PrivateKey
	if err := sk.Unpack(myIdentity.KEMPriv); err != nil {
		return nil, ErrIdentityCorrupted
	}
	ss := make([]byte, mlkem768.SharedKeySize)
	sk.DecapsulateTo(ss, env.KEMCiphertext)

	kEnv := deriveEnvelopeKey(ss, dealer, recipient, context)
	stream := transcript.CShake256(kEnv[:], sealedSize, transcript.FuncName, envStreamTag)
	plaintext := make([]byte, sealedSize)
	for i := range env.Sealed {
		plaintext[i] = env.Sealed[i] ^ stream[i]
	}
	share := make([]byte, shareLen)
	copy(share, plaintext[:shareLen])
	authInput := append(append(append([]byte{}, dealer[:]...), recipient[:]...), share...)
	want := transcript.KMAC256(kEnv[:], authInput, envAuthTagSize, envAuthTag)
	if !ctEqual(want, plaintext[shareLen:]) {
		return nil, ErrEnvelopeAuthBad
	}
	return share, nil
}

// deriveEnvelopeKey expands the KEM shared secret into a 32-byte
// envelope-encryption key bound to (dealer, recipient, context).
func deriveEnvelopeKey(ss []byte, dealer, recipient NodeID, context [32]byte) [32]byte {
	info := append([]byte(envKeyTag), dealer[:]...)
	info = append(info, recipient[:]...)
	info = append(info, context[:]...)
	r := hkdf.New(sha3.New256, ss, dealer[:], info)
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}
