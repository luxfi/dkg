// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ring

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Profile is the ONE place a scheme's parameters live. The generic DKG (vss/,
// blame/) is parameterized solely by a *Profile; nothing downstream knows
// whether it is running Ringtail or ML-DSA. New schemes get a new Profile —
// they are never bolted onto an existing one (DESIGN.md "orthogonal,
// composition over inheritance").
//
// A Profile bundles five orthogonal concerns:
//  1. the ring R_q (degree n, modulus q),
//  2. the module shape (K commit rows, L secret cols),
//  3. the two public Pedersen matrices A, B ∈ R_q^{K×L} (NTT-Mont),
//  4. the secret/blinding distribution χ (SampleSecretVec),
//  5. the public-key finalizer T ↦ pk (KeyFinalize).
type Profile struct {
	Name string
	Ring *Ring
	K    int // commit / module rows (corona 8, ml-dsa 6)
	L    int // secret / share cols  (corona 7, ml-dsa 5)

	// Eta is the χ_η coefficient bound for uniform-η secret schemes (ML-DSA
	// η=4); 0 for Gaussian schemes (Ringtail). The Mithril RSS DKG (rss/) reads
	// it to sample short subset secrets of the right module shape; the generic
	// Pedersen-VSS DKG uses SampleSecretVec and ignores it. One place for η.
	Eta uint64

	// A, B are the public Pedersen matrices, NTT-Montgomery form, K×L. Both
	// are nothing-up-my-sleeve: every party derives them from public tags, so
	// there is no trusted setup of the public matrices. (The ML-DSA consumer
	// may override A with ExpandA(rho); see WithMatrices.)
	A Matrix
	B Matrix

	// SampleSecretVec draws one length-L vector in standard coefficient form
	// from the scheme secret distribution χ (Ringtail Gaussian / ML-DSA
	// uniform-η), driven by prng. The DKG calls it 2t times per party (t for
	// the secret polynomial f_i, t for the blinding polynomial g_i).
	SampleSecretVec func(prng PRNG) Vector

	// KeyFinalize maps the aggregated public commit T = Σ_i C_{i,0} ∈ R_q^K
	// (standard coefficient form) to the scheme group public key. This is the
	// only place the Ringtail-β vs ML-DSA-t1 difference appears.
	KeyFinalize func(p *Profile, T Vector) (*GroupPublicKey, error)
}

// GroupPublicKey is the dealerless DKG output. T is the canonical
// no-reconstruct root: the aggregated public Pedersen commit Σ_i C_{i,0} =
// A·s1 + B·u, derived WITHOUT ever reconstructing s1 or u. Finalized is the
// scheme-specific public-key vector (Ringtail bTilde / ML-DSA t1); Aux carries
// scheme aux material the signer needs (ML-DSA t0; nil for Ringtail).
type GroupPublicKey struct {
	Scheme    string
	T         Vector // Σ_i C_{i,0} (standard coeff form, R_q^K) — the root
	Finalized Vector // scheme pubkey vector (Ringtail bTilde / ML-DSA t1)
	Aux       Vector // scheme aux (ML-DSA t0); nil for Ringtail
}

// Encode returns a canonical, byte-stable serialization of the finalized
// public key for transcript binding and chain commitment. Format:
// scheme-tag-len ‖ scheme-tag ‖ len(Finalized) ‖ (poly coeffs LE-u64)×.
func (g *GroupPublicKey) Encode() []byte {
	var buf bytes.Buffer
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(g.Scheme)))
	buf.Write(b4[:])
	buf.WriteString(g.Scheme)
	binary.BigEndian.PutUint32(b4[:], uint32(len(g.Finalized)))
	buf.Write(b4[:])
	for _, p := range g.Finalized {
		for _, c := range p.Coeffs[0] {
			var b8 [8]byte
			binary.LittleEndian.PutUint64(b8[:], c)
			buf.Write(b8[:])
		}
	}
	return buf.Bytes()
}

// Validate checks a Profile is internally consistent before use.
func (p *Profile) Validate() error {
	if p == nil {
		return errors.New("dkg/ring: nil profile")
	}
	if p.Ring == nil {
		return errors.New("dkg/ring: profile has nil ring")
	}
	if p.K < 1 || p.L < 1 {
		return errors.New("dkg/ring: profile module shape must be K,L >= 1")
	}
	if len(p.A) != p.K || len(p.B) != p.K {
		return errors.New("dkg/ring: profile matrices must have K rows")
	}
	for i := 0; i < p.K; i++ {
		if len(p.A[i]) != p.L || len(p.B[i]) != p.L {
			return errors.New("dkg/ring: profile matrices must have L cols")
		}
	}
	if p.SampleSecretVec == nil {
		return errors.New("dkg/ring: profile missing SampleSecretVec")
	}
	if p.KeyFinalize == nil {
		return errors.New("dkg/ring: profile missing KeyFinalize")
	}
	return nil
}

// WithMatrices returns a shallow copy of p with the public matrices replaced.
// The ML-DSA consumer uses this to bind A = ExpandA(rho) from the chain genesis
// seed in place of the default nothing-up-my-sleeve A, without forking the
// profile. B is typically left as the domain-separated default.
func (p *Profile) WithMatrices(a, b Matrix) *Profile {
	cp := *p
	cp.A = a
	cp.B = b
	return &cp
}
