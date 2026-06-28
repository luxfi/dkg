// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package nonce is the robust nonce-ticket lifecycle of luxfi/dkg (malicious-
// hardening component 9). Threshold ML-DSA signing (TALUS) consumes ONE-TIME
// offline-preprocessed nonces; reusing a nonce across two messages leaks the
// long-term key, so the lifecycle must guarantee:
//
//   - offline inventory: nonce slots are precomputed before any message is known
//     (the expensive dealerless nonce DKG runs offline);
//   - replay binding: a ticket is bound to a specific (epoch, committee, policy,
//     digest) by an unforgeable id = transcript.Hash(...), so it can authorize a
//     signature for that context and NO other;
//   - consume-once: a ticket is accepted at most once; a second presentation is
//     rejected (the consume-ledger is the in-reference stand-in for the chain's
//     spent-nonce set);
//   - expiry: a ticket past its deadline is rejected, so a stale offline nonce
//     cannot be revived.
//
// The ticket carries NO secret nonce material — the nonce shares live in the
// (separate) dealerless nonce DKG. A ticket is the PUBLIC, signed lifecycle
// token that binds and tracks one nonce slot. Authenticity rides channel.Sign
// under channel.CtxNonce; the binding rides transcript (SP 800-185).
package nonce

import (
	"errors"
	"sync"
	"time"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/transcript"
)

// Errors.
var (
	ErrNoneAvailable = errors.New("dkg/nonce: inventory exhausted (no available slot)")
	ErrExpired       = errors.New("dkg/nonce: ticket past its expiry")
	ErrConsumed      = errors.New("dkg/nonce: ticket already consumed (replay)")
	ErrUnknownTicket = errors.New("dkg/nonce: ticket not issued by this inventory")
	ErrBinding       = errors.New("dkg/nonce: ticket id does not match its (epoch,committee,policy,digest)")
	ErrSignature     = errors.New("dkg/nonce: ticket issuer signature invalid")
	ErrShape         = errors.New("dkg/nonce: invalid inventory size")
)

// Binding is the four values a nonce ticket is replay-bound to. Distinct
// bindings yield distinct ids, so a ticket can never authorize a signature for a
// different epoch, committee, policy, or message digest.
type Binding struct {
	Epoch     uint64
	Committee [32]byte // hash of the committee validator set
	Policy    [32]byte // hash of the signing policy (tier, params)
	Digest    [32]byte // the message digest the nonce signs over
}

// TicketID is the replay-bound id: a TupleHash256-framed transcript hash over
// the binding. Pure function — any verifier recomputes it to check a ticket.
func (b Binding) TicketID() [32]byte {
	t := transcript.NewWithDomain(transcript.FuncName, "LUX-DKG-NONCE-TICKET-V1")
	t.AppendU64("epoch", b.Epoch)
	t.AppendHash("committee", b.Committee)
	t.AppendHash("policy", b.Policy)
	t.AppendHash("digest", b.Digest)
	return t.Hash()
}

// Ticket is a signed, replay-bound, one-time nonce authorization. Index names
// the offline inventory slot; Expiry is a unix deadline (0 = none); Sig is the
// issuer's ML-DSA-65 signature over SigningBytes under channel.CtxNonce.
type Ticket struct {
	ID      [32]byte
	Binding Binding
	Index   uint64
	Expiry  int64
	Issuer  channel.NodeID
	Sig     []byte
}

// SigningBytes are the canonical to-be-signed bytes: the id (which already binds
// epoch/committee/policy/digest), the slot index, the expiry, and the issuer.
func (t *Ticket) SigningBytes() []byte {
	tr := transcript.NewWithDomain(transcript.FuncName, "LUX-DKG-NONCE-SIG-V1")
	tr.AppendHash("id", t.ID)
	tr.AppendU64("index", t.Index)
	tr.AppendU64("expiry", uint64(t.Expiry))
	tr.Append("issuer", t.Issuer[:])
	h := tr.Hash48() // 48-byte tag, matches the channel signing convention
	return h[:]
}

// VerifyTicket is the stateless third-party check: the id matches its binding
// AND the issuer's signature is valid. It does NOT check consume-once or expiry
// (those need state / a clock) — Inventory.Consume composes all three.
func VerifyTicket(t *Ticket, dir channel.IdentityDirectory) error {
	if t == nil {
		return ErrUnknownTicket
	}
	if t.Binding.TicketID() != t.ID {
		return ErrBinding
	}
	pub := dir.Get(t.Issuer)
	if pub == nil || !channel.Verify(pub, channel.CtxNonce, t.SigningBytes(), t.Sig) {
		return ErrSignature
	}
	return nil
}

// state is one offline slot's lifecycle position.
type state uint8

const (
	available state = iota // precomputed, unbound
	bound                  // bound to a context, awaiting consume
	consumed               // consumed once; terminal
)

type slot struct {
	st     state
	id     [32]byte
	expiry int64
}

// Inventory is the issuer's offline nonce pool + consume-ledger. It binds an
// available slot to a signing context (issuing a signed Ticket) and enforces
// consume-once + expiry. Safe for concurrent use.
type Inventory struct {
	mu       sync.Mutex
	issuer   *channel.IdentityKey
	issuerID channel.NodeID
	slots    []slot
	byID     map[[32]byte]int // ticket id → slot index (issued tickets)
	clock    func() int64     // injectable unix clock (nil ⇒ time.Now)
}

// NewInventory precomputes `size` available nonce slots for issuer. size must be
// >= 1. (In a deployment the dealerless nonce DKG fills the slots' secret
// material offline; here a slot is the public lifecycle handle.)
func NewInventory(issuer *channel.IdentityKey, issuerID channel.NodeID, size int) (*Inventory, error) {
	if issuer == nil || size < 1 {
		return nil, ErrShape
	}
	return &Inventory{
		issuer:   issuer,
		issuerID: issuerID,
		slots:    make([]slot, size),
		byID:     make(map[[32]byte]int, size),
	}, nil
}

func (inv *Inventory) now() int64 {
	if inv.clock != nil {
		return inv.clock()
	}
	return time.Now().Unix()
}

// Available returns the number of slots not yet bound.
func (inv *Inventory) Available() int {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	c := 0
	for i := range inv.slots {
		if inv.slots[i].st == available {
			c++
		}
	}
	return c
}

// Bind binds the lowest available slot to b and returns a signed Ticket. ttl is
// the seconds-from-now expiry (0 ⇒ no expiry). The slot moves available→bound;
// a slot binds to exactly one context, so the same nonce can never be bound to
// two messages.
func (inv *Inventory) Bind(b Binding, ttl int64) (*Ticket, error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	idx := -1
	for i := range inv.slots {
		if inv.slots[i].st == available {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNoneAvailable
	}
	id := b.TicketID()
	var expiry int64
	if ttl > 0 {
		expiry = inv.now() + ttl
	}
	t := &Ticket{ID: id, Binding: b, Index: uint64(idx), Expiry: expiry, Issuer: inv.issuerID}
	sig, err := channel.Sign(inv.issuer, channel.CtxNonce, t.SigningBytes())
	if err != nil {
		return nil, err
	}
	t.Sig = sig
	inv.slots[idx] = slot{st: bound, id: id, expiry: expiry}
	inv.byID[id] = idx
	return t, nil
}

// Consume validates and consumes a ticket against this inventory's ledger:
// stateless verification (binding + issuer signature), then expiry, then
// consume-once. On success the slot moves bound→consumed and a second Consume of
// the same ticket returns ErrConsumed. dir supplies the issuer's public key.
func (inv *Inventory) Consume(t *Ticket, dir channel.IdentityDirectory) error {
	if err := VerifyTicket(t, dir); err != nil {
		return err
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	idx, ok := inv.byID[t.ID]
	if !ok {
		return ErrUnknownTicket
	}
	s := &inv.slots[idx]
	if s.st == consumed {
		return ErrConsumed
	}
	if s.expiry != 0 && inv.now() > s.expiry {
		return ErrExpired
	}
	s.st = consumed
	return nil
}
