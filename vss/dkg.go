// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package vss is the dealerless, no-reconstruct Pedersen-VSS distributed key
// generation at the heart of luxfi/dkg. It is GENERIC over a *ring.Profile: the
// same three-round protocol produces a Ringtail group key or a FIPS-204-shaped
// ML-DSA group key depending only on the profile passed in.
//
// The headline invariant (DESIGN.md): NO-RECONSTRUCT. No party ever forms the
// master secret s1 = Σ_i c_{i,0}, the blinding u = Σ_i r_{i,0}, or any seed. A
// party retains ONLY its own aggregated share s_j = Σ_i f_i(j); the group
// public key is derived from the aggregated PUBLIC commit T = Σ_i C_{i,0} =
// A·s1 + B·u (KeyFinalize), never by reconstructing a secret. This package
// contains NO Lagrange interpolation / reconstruction of the secret in its
// output path — verified structurally by TestNoReconstruct_SourceStructural.
//
// Three rounds (DESIGN.md vss/):
//   - Round 1 (commit & deal): sample f_i, g_i over R_q^L with χ; broadcast
//     Pedersen commits C_{i,k} = A·c_{i,k} + B·r_{i,k}; KEM-seal the per-
//     recipient SHARE (f_i(j), g_i(j)) — never the contribution. Each party
//     also publishes a commit-then-reveal commitment (component 8) so it fixes
//     its commits before seeing others'.
//   - Round 2 (equivocation gate): every recipient broadcasts the cSHAKE256
//     commit digest of each dealer's commit vector; disagreement across
//     recipients ⇒ the dealer equivocated (component 5).
//   - Round 3 (verify & aggregate): verify the Pedersen identity for every
//     received share (component 6 malformed-share rejection); aggregate s_j and
//     T; KeyFinalize T into the group public key.
package vss

import (
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/ring"
	"github.com/luxfi/dkg/transcript"
)

// Domain tags bound into the equivocation digest and the session transcript.
const (
	tagCommitDigest = "LUX-DKG-COMMIT-DIGEST-V1"
	tagTranscript   = "LUX-DKG-SESSION-V1"
)

// Errors returned by the DKG.
var (
	ErrShape           = errors.New("dkg/vss: invalid (n,t) shape: need n>=2 and 1<=t<n")
	ErrIndex           = errors.New("dkg/vss: party index out of range")
	ErrMissingDealer   = errors.New("dkg/vss: missing dealer contribution")
	ErrMissingIdentity = errors.New("dkg/vss: missing identity key for party")
	ErrShareVerify     = errors.New("dkg/vss: Pedersen share verification failed")
	ErrEquivocation    = errors.New("dkg/vss: dealer equivocated (commit-digest disagreement)")
)

// Party is one party's DKG session state.
type Party struct {
	profile  *ring.Profile
	id       channel.NodeID
	identity *channel.IdentityKey
	index    int // 0-based; evaluation point = index+1
	n, t     int
	dir      channel.IdentityDirectory
	nodes    []channel.NodeID // index → NodeID, canonical committee order
	context  [32]byte         // committee/era root binding all envelopes

	// stashed across Round1 → Round3
	cCoeffs []ring.Vector
	rCoeffs []ring.Vector
	commits []ring.Vector
	nonce   [32]byte
}

// NewParty constructs a session for the party at index over an n-party
// committee with threshold t. nodes lists every committee NodeID in canonical
// order (nodes[index] == id). dir resolves peer identity public keys. context
// is the era/committee root (e.g. a chain transcript hash) binding every
// envelope to this ceremony.
func NewParty(
	profile *ring.Profile,
	id channel.NodeID,
	identity *channel.IdentityKey,
	index, n, t int,
	nodes []channel.NodeID,
	dir channel.IdentityDirectory,
	context [32]byte,
) (*Party, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if n < 2 || t < 1 || t >= n {
		return nil, ErrShape
	}
	if index < 0 || index >= n || len(nodes) != n {
		return nil, ErrIndex
	}
	if identity == nil {
		return nil, ErrMissingIdentity
	}
	return &Party{
		profile: profile, id: id, identity: identity,
		index: index, n: n, t: t, nodes: nodes, dir: dir, context: context,
	}, nil
}

// Round1Out is one party's Round-1 production. Commits and Commitment are
// broadcast; Envelopes[j] is sent privately to recipient j. The reveal nonce is
// retained in the Party until Reveal().
type Round1Out struct {
	DealerIndex int
	Commits     []ring.Vector              // C_{i,k}, k=0..t-1 (plain-NTT)
	Commitment  channel.Commitment         // commit-then-reveal binding (phase A)
	Envelopes   map[int]channel.Envelope   // recipient index → sealed (share ‖ blind)
}

// Round1 samples the secret/blinding polynomials, computes the Pedersen
// commits, seals the per-recipient share+blind into authenticated envelopes,
// and forms the commit-then-reveal commitment. rng drives sampling and the
// (random) per-recipient KEM encapsulation.
func (p *Party) Round1(rng io.Reader) (*Round1Out, error) {
	prof := p.profile
	r := prof.Ring
	n := prof.Ring.N()

	// Per-party sampling PRNG seed from rng, so the χ draws are deterministic
	// given the seed (KAT-replayable) and independent across parties.
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return nil, fmt.Errorf("dkg/vss: Round1 seed: %w", err)
	}
	prng, err := ring.NewKeyedPRNG(seed)
	if err != nil {
		return nil, err
	}

	// Sample f_i and g_i: t coefficient vectors each, χ over R_q^L.
	p.cCoeffs = make([]ring.Vector, p.t)
	for k := 0; k < p.t; k++ {
		p.cCoeffs[k] = prof.SampleSecretVec(prng)
	}
	p.rCoeffs = make([]ring.Vector, p.t)
	for k := 0; k < p.t; k++ {
		p.rCoeffs[k] = prof.SampleSecretVec(prng)
	}

	// Pedersen commits.
	p.commits = computeCommits(prof, p.cCoeffs, p.rCoeffs)

	// Seal per-recipient share+blind. Evaluate f_i, g_i at every recipient
	// point (index+1) and KEM-seal ONLY the share (no contribution).
	envs := make(map[int]channel.Envelope, p.n)
	for j := 0; j < p.n; j++ {
		share := hornerEval(r, p.cCoeffs, uint64(j+1))
		blind := hornerEval(r, p.rCoeffs, uint64(j+1))
		wire := serializeShareBlind(share, blind, prof.L, n)
		recipPub := p.dir.Get(p.nodes[j])
		if recipPub == nil {
			return nil, fmt.Errorf("dkg/vss: Round1: no identity for recipient %d", j)
		}
		env, err := channel.Seal(p.id, p.nodes[j], p.context, wire, recipPub.KEMPub, nil, rng)
		if err != nil {
			return nil, fmt.Errorf("dkg/vss: Round1 seal to %d: %w", j, err)
		}
		envs[j] = env
	}

	// Commit-then-reveal: commit to the public commit vector before reveal.
	nonce, err := channel.NewNonce(rng)
	if err != nil {
		return nil, err
	}
	p.nonce = nonce
	commitBytes := serializeCommits(p.commits, prof.K, n)
	commitment := channel.Commit(commitBytes, nonce)

	return &Round1Out{
		DealerIndex: p.index,
		Commits:     p.commits,
		Commitment:  commitment,
		Envelopes:   envs,
	}, nil
}

// Reveal returns this party's (commit bytes, nonce) opening for the commit-
// then-reveal phase B. Other parties verify it against the Round-1 Commitment.
func (p *Party) Reveal() (commitBytes []byte, nonce [32]byte) {
	n := p.profile.Ring.N()
	return serializeCommits(p.commits, p.profile.K, n), p.nonce
}

// CommitDigest returns the cSHAKE256 equivocation digest of a dealer's commit
// vector (Round-2 gate, component 5). Every honest recipient computes the same
// digest from the same commits; disagreement names an equivocating dealer.
func (p *Party) CommitDigest(commits []ring.Vector) [32]byte {
	payload := serializeCommits(commits, p.profile.K, p.profile.Ring.N())
	return transcript.CommitDigest(tagCommitDigest, payload)
}

// VerifyFault carries the publicly-checkable evidence of a Round-3 Pedersen
// failure: the dealer whose (share, blind) did not satisfy the identity against
// its commits, at this recipient's point. The caller hands it to the blame
// layer to mint a signed ComplaintBadDelivery.
type VerifyFault struct {
	DealerIndex    int
	RecipientIndex int
	Share          ring.Vector
	Blind          ring.Vector
	Commits        []ring.Vector
}

// ShareResult is a party's Round-3 output: its retained secret share s_j, its
// blinding share u_j, and the group public key. NO master secret appears — s_j
// and u_j are Shamir shares of s1 and u, never s1 or u themselves.
type ShareResult struct {
	RecipientIndex int
	Share          ring.Vector // s_j = Σ_i f_i(j): the secret share retained
	Blind          ring.Vector // u_j = Σ_i g_i(j): the blinding share retained
	GroupKey       *ring.GroupPublicKey
}

// DealerInput bundles, for one dealer i, the dealer's public commit vector and
// the (share, blind) this party opened from the dealer's sealed envelope.
type DealerInput struct {
	Commits []ring.Vector
	Share   ring.Vector
	Blind   ring.Vector
}

// Round3 verifies the Pedersen identity for every dealer's contribution to this
// party, aggregates the verified shares into s_j, aggregates the public commits
// into T, and finalizes the group key. On the first dealer whose share fails
// verification it returns a VerifyFault (component 6) and no result. Dealers are
// iterated in ascending index order so every honest party blames the same first
// deviator deterministically.
func (p *Party) Round3(inputs map[int]*DealerInput) (*ShareResult, *VerifyFault, error) {
	prof := p.profile
	point := uint64(p.index + 1)

	for i := 0; i < p.n; i++ {
		in := inputs[i]
		if in == nil {
			return nil, nil, fmt.Errorf("%w: dealer %d", ErrMissingDealer, i)
		}
		if !verifyPedersen(prof, in.Share, in.Blind, in.Commits, point) {
			return nil, &VerifyFault{
				DealerIndex: i, RecipientIndex: p.index,
				Share: in.Share, Blind: in.Blind, Commits: in.Commits,
			}, ErrShareVerify
		}
	}

	// Aggregate (verified) shares, blinds, and public commits.
	shares := make([]ring.Vector, p.n)
	blinds := make([]ring.Vector, p.n)
	dealerCommits := make([][]ring.Vector, p.n)
	for i := 0; i < p.n; i++ {
		shares[i] = inputs[i].Share
		blinds[i] = inputs[i].Blind
		dealerCommits[i] = inputs[i].Commits
	}
	sShare := aggregateShare(prof, shares)
	uShare := aggregateShare(prof, blinds)
	T := aggregateGroupCommit(prof, dealerCommits)

	gk, err := prof.KeyFinalize(prof, T)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg/vss: KeyFinalize: %w", err)
	}
	return &ShareResult{RecipientIndex: p.index, Share: sShare, Blind: uShare, GroupKey: gk}, nil, nil
}

// OpenDealerShare opens the sealed envelope dealer i addressed to this party,
// recovering (share, blind). Wraps channel.Open with the profile's share width.
func (p *Party) OpenDealerShare(dealerIndex int, env channel.Envelope) (share, blind ring.Vector, err error) {
	prof := p.profile
	n := prof.Ring.N()
	wire, err := channel.Open(p.nodes[dealerIndex], p.id, p.context, env, shareWireLen(prof.L, n), p.identity)
	if err != nil {
		return nil, nil, err
	}
	return deserializeShareBlind(prof.Ring, wire, prof.L, n)
}

// EvalPoint returns this party's Shamir evaluation point (index + 1).
func (p *Party) EvalPoint() uint64 { return uint64(p.index + 1) }

// Index returns the party's 0-based committee index.
func (p *Party) Index() int { return p.index }
