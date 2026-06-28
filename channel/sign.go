// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package channel

import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// sign.go — ML-DSA-65 authentication of broadcasts and complaints.
//
// Every authenticated message in the DKG (Round-1.5 commit-digest broadcasts,
// blame complaints, session-establishment encapsulations) is signed under the
// sender's long-term ML-DSA-65 identity key with a domain-separating context.
// A third party (chain validator, slashing module) verifies against the
// sender's published identity public key. The context string is mandatory and
// non-empty so a signature minted for one purpose never validates for another.

// Context strings binding a signature to its purpose. Reusing a signature
// across purposes is a context mismatch at verify time.
const (
	// CtxBroadcast authenticates a Round-1.5 commit-digest broadcast.
	CtxBroadcast = "LUX-DKG-BROADCAST-V1"
	// CtxComplaint authenticates a blame complaint.
	CtxComplaint = "LUX-DKG-COMPLAINT-V1"
	// CtxNonce authenticates a nonce-ticket lifecycle event (issue / consume),
	// binding it to its replay-bound (epoch, committee, policy, digest) id so a
	// ticket minted for one signing context never validates for another.
	CtxNonce = "LUX-DKG-NONCE-V1"
)

// Sign produces an ML-DSA-65 signature over msg under ctx using the party's
// long-term identity secret key. ctx must be non-empty.
func Sign(identity *IdentityKey, ctx string, msg []byte) ([]byte, error) {
	if identity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if len(ctx) == 0 {
		return nil, ErrIdentityCorrupted
	}
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(identity.MLDSAPriv); err != nil {
		return nil, ErrIdentityCorrupted
	}
	sig := make([]byte, mldsa65.SignatureSize)
	// Deterministic (randomized=false) so KAT replay reproduces the bytes.
	if err := mldsa65.SignTo(&priv, msg, []byte(ctx), false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify checks an ML-DSA-65 signature over msg under ctx against a party's
// published identity public key. Returns false on any malformed input.
func Verify(pub *IdentityPublicKey, ctx string, msg, sig []byte) bool {
	if pub == nil || len(pub.MLDSAPub) != mldsa65.PublicKeySize || len(ctx) == 0 {
		return false
	}
	var dpub mldsa65.PublicKey
	if err := dpub.UnmarshalBinary(pub.MLDSAPub); err != nil {
		return false
	}
	return mldsa65.Verify(&dpub, msg, []byte(ctx), sig)
}

// DirectoryVerifier adapts an IdentityDirectory to the blame layer's
// signature-verification need: look the accuser up by NodeID and verify the
// complaint signature under CtxComplaint. Returns false if the party is unknown
// or the signature is invalid — there is no implicit skip-verification path.
type DirectoryVerifier struct {
	Dir IdentityDirectory
}

// VerifyComplaintSignature reports whether sig is a valid complaint signature
// by accuser over transcriptBytes.
func (v DirectoryVerifier) VerifyComplaintSignature(accuser NodeID, transcriptBytes, sig []byte) bool {
	pub := v.Dir.Get(accuser)
	if pub == nil {
		return false
	}
	return Verify(pub, CtxComplaint, transcriptBytes, sig)
}
