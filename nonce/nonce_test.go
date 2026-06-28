// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package nonce

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/channel"
)

// issuer builds one identity with a synthetic NodeID and a directory holding it.
func issuer(t *testing.T) (*channel.IdentityKey, channel.NodeID, channel.IdentityDirectory) {
	t.Helper()
	k, err := channel.GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := channel.NodeID{0x01}
	dir, _ := channel.NewIdentityDirectory(map[channel.NodeID]*channel.IdentityPublicKey{id: k.PublicKey()})
	return k, id, dir
}

func bindingFor(digest byte) Binding {
	return Binding{
		Epoch:     7,
		Committee: [32]byte{0xC0},
		Policy:    [32]byte{0x90},
		Digest:    [32]byte{digest},
	}
}

// TestLifecycle_BindConsumeOnce: a bound ticket verifies, consumes once, and a
// second consume is rejected as a replay.
func TestLifecycle_BindConsumeOnce(t *testing.T) {
	k, id, dir := issuer(t)
	inv, err := NewInventory(k, id, 4)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Available() != 4 {
		t.Fatalf("Available: got %d want 4", inv.Available())
	}
	tk, err := inv.Bind(bindingFor(0xAA), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTicket(tk, dir); err != nil {
		t.Fatalf("VerifyTicket: %v", err)
	}
	if inv.Available() != 3 {
		t.Fatalf("Available after bind: got %d want 3", inv.Available())
	}
	if err := inv.Consume(tk, dir); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := inv.Consume(tk, dir); err != ErrConsumed {
		t.Fatalf("replay Consume: got %v want ErrConsumed", err)
	}
}

// TestReplayBinding: a ticket bound to one digest cannot be re-pointed at another
// — mutating any binding field breaks the id and is rejected (ErrBinding).
func TestReplayBinding(t *testing.T) {
	k, id, dir := issuer(t)
	inv, _ := NewInventory(k, id, 2)
	tk, _ := inv.Bind(bindingFor(0xAA), 0)

	// Swap the message digest the adversary wants to (mis)use this nonce for.
	forged := *tk
	forged.Binding.Digest = [32]byte{0xBB}
	if err := VerifyTicket(&forged, dir); err != ErrBinding {
		t.Fatalf("digest swap: got %v want ErrBinding", err)
	}
	// Same for epoch / committee / policy.
	for _, mut := range []func(*Ticket){
		func(x *Ticket) { x.Binding.Epoch = 8 },
		func(x *Ticket) { x.Binding.Committee = [32]byte{0xFF} },
		func(x *Ticket) { x.Binding.Policy = [32]byte{0xFF} },
	} {
		f := *tk
		mut(&f)
		if err := VerifyTicket(&f, dir); err != ErrBinding {
			t.Fatalf("binding mutation: got %v want ErrBinding", err)
		}
	}
}

// TestTamperedSignature: any change to the signed fields (or a bad signature) is
// rejected as ErrSignature once the binding id is kept consistent.
func TestTamperedSignature(t *testing.T) {
	k, id, dir := issuer(t)
	inv, _ := NewInventory(k, id, 2)
	tk, _ := inv.Bind(bindingFor(0xAA), 0)

	bad := *tk
	bad.Sig = append([]byte(nil), tk.Sig...)
	bad.Sig[0] ^= 0xFF
	if err := VerifyTicket(&bad, dir); err != ErrSignature {
		t.Fatalf("flipped sig: got %v want ErrSignature", err)
	}
	// Tampering the index changes SigningBytes but not the id ⇒ signature fails.
	bad2 := *tk
	bad2.Index = 99
	if err := VerifyTicket(&bad2, dir); err != ErrSignature {
		t.Fatalf("index tamper: got %v want ErrSignature", err)
	}
}

// TestExpiry: a ticket past its deadline is rejected at consume.
func TestExpiry(t *testing.T) {
	k, id, dir := issuer(t)
	inv, _ := NewInventory(k, id, 2)
	now := int64(1000)
	inv.clock = func() int64 { return now }

	tk, _ := inv.Bind(bindingFor(0xAA), 60) // expires at 1060
	now = 1059
	if err := inv.Consume(tk, dir); err != nil {
		t.Fatalf("consume before expiry: %v", err)
	}
	// Fresh ticket, advance past expiry.
	tk2, _ := inv.Bind(bindingFor(0xBB), 60) // expires at 1119
	now = 1120
	if err := inv.Consume(tk2, dir); err != ErrExpired {
		t.Fatalf("consume after expiry: got %v want ErrExpired", err)
	}
}

// TestExhaustionAndUnknown: binding past inventory size fails; consuming a ticket
// this inventory never issued fails as unknown.
func TestExhaustionAndUnknown(t *testing.T) {
	k, id, dir := issuer(t)
	inv, _ := NewInventory(k, id, 1)
	if _, err := inv.Bind(bindingFor(0x01), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Bind(bindingFor(0x02), 0); err != ErrNoneAvailable {
		t.Fatalf("exhaustion: got %v want ErrNoneAvailable", err)
	}

	// A ticket issued by a DIFFERENT inventory is unknown here (but still
	// stateless-verifies, since it is validly signed + bound).
	inv2, _ := NewInventory(k, id, 1)
	other, _ := inv2.Bind(bindingFor(0x03), 0)
	if err := VerifyTicket(other, dir); err != nil {
		t.Fatalf("foreign ticket should stateless-verify: %v", err)
	}
	if err := inv.Consume(other, dir); err != ErrUnknownTicket {
		t.Fatalf("foreign consume: got %v want ErrUnknownTicket", err)
	}
}

// TestCrossContextDistinctIDs: distinct (epoch,committee,policy,digest) bindings
// yield distinct ids — the core replay-isolation property.
func TestCrossContextDistinctIDs(t *testing.T) {
	base := bindingFor(0xAA)
	id0 := base.TicketID()
	variants := []Binding{
		{Epoch: 8, Committee: base.Committee, Policy: base.Policy, Digest: base.Digest},
		{Epoch: base.Epoch, Committee: [32]byte{0x01}, Policy: base.Policy, Digest: base.Digest},
		{Epoch: base.Epoch, Committee: base.Committee, Policy: [32]byte{0x01}, Digest: base.Digest},
		{Epoch: base.Epoch, Committee: base.Committee, Policy: base.Policy, Digest: [32]byte{0x01}},
	}
	for i, v := range variants {
		if v.TicketID() == id0 {
			t.Fatalf("variant %d collided with base id", i)
		}
	}
}
