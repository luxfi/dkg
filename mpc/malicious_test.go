// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/channel"
)

// ids builds n ML-DSA-65 identities with synthetic NodeIDs 1..n and a directory,
// mirroring the blame package's test harness.
func ids(t *testing.T, n int) ([]*channel.IdentityKey, []channel.NodeID, channel.IdentityDirectory) {
	t.Helper()
	keys := make([]*channel.IdentityKey, n)
	nodes := make([]channel.NodeID, n)
	entries := make(map[channel.NodeID]*channel.IdentityPublicKey, n)
	for i := 0; i < n; i++ {
		k, err := channel.GenerateIdentity(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
		nodes[i] = channel.NodeID{byte(i + 1)}
		entries[nodes[i]] = k.PublicKey()
	}
	dir, _ := channel.NewIdentityDirectory(entries)
	return keys, nodes, dir
}

// sign is shorthand for an accused party signing its broadcast commitment.
func sign(t *testing.T, k *channel.IdentityKey, commit []byte) []byte {
	t.Helper()
	sig, err := channel.Sign(k, channel.CtxBroadcast, commit)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestCheckDegree_ExactMembership: a genuine degree-(t-1) sharing is a codeword;
// a single off-polynomial share is rejected; the test is exact regardless of
// which position is tampered.
func TestCheckDegree_ExactMembership(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	shares, err := f.ShareScalar(424242, pts, th, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !f.CheckDegree(pts, shares, th) {
		t.Fatal("honest degree-(t-1) sharing rejected by CheckDegree")
	}
	for pos := 0; pos < n; pos++ {
		bad := append([]Elem(nil), shares...)
		bad[pos] = f.Add(bad[pos], 1) // bump one share off the polynomial
		if f.CheckDegree(pts, bad, th) {
			t.Fatalf("off-polynomial share at pos %d accepted by CheckDegree", pos)
		}
	}
}

// TestMulCommitted_HonestEqualsSemiHonest: the committed multiplication produces
// the same product on honest input as the semi-honest one (any t shares
// reconstruct x·y), and reports no fault.
func TestMulCommitted_HonestEqualsSemiHonest(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	x, y := Elem(111111), Elem(222222)
	xs, _ := f.ShareScalar(x, pts, th, rand.Reader)
	ys, _ := f.ShareScalar(y, pts, th, rand.Reader)
	zs, fault, err := f.MulSharesCommitted(xs, ys, pts, th, rand.Reader)
	if err != nil || fault != nil {
		t.Fatalf("honest committed mul: err=%v fault=%v", err, fault)
	}
	want := f.Mul(x, y)
	for _, idx := range [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}} {
		got, _ := f.InterpolateAtZeroSubset(pts, zs, idx)
		if got != want {
			t.Fatalf("committed mul subset %v: got %d want %d", idx, got, want)
		}
	}
}

// TestReshare_DeviationDetectedAndBlamed: closer (a). A malformed committed
// re-share (off-polynomial) is rejected with a ReshareFault naming the dealer;
// the fault becomes a verifiable ReasonBadReshare complaint that RecheckReshare
// confirms — while an HONEST re-share is NOT justified (no false accusation).
func TestReshare_DeviationDetectedAndBlamed(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	keys, nodes, dir := ids(t, n)
	session := [32]byte{0xCA}

	// Build n honest committed re-shares, then corrupt dealer 2's into a
	// non-codeword (still self-consistently committed, as a malicious dealer
	// would broadcast a commitment to its bad vector).
	deals := make([]*ReshareDeal, n)
	for i := 0; i < n; i++ {
		d, err := f.DealReshare(Elem(1000+i), pts, th, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		deals[i] = d
	}
	const badDealer = 2
	bad := append([]Elem(nil), deals[badDealer].Shares...)
	bad[4] = f.Add(bad[4], 7) // off the degree-(t-1) polynomial
	nonce, _ := NewNonce(rand.Reader)
	deals[badDealer] = &ReshareDeal{Shares: bad, Nonce: nonce, Commit: CommitReshare(bad, nonce)}

	_, fault, err := f.CombineCommittedReshares(deals, pts, th)
	if err != nil {
		t.Fatal(err)
	}
	if fault == nil || fault.Dealer != badDealer {
		t.Fatalf("expected ReshareFault on dealer %d, got %+v", badDealer, fault)
	}

	// The dealer signed its (bad) commitment broadcast; mint + verify the complaint.
	fault.Sig = sign(t, keys[badDealer], fault.Commit)
	c, err := NewReshareComplaint(fault, session, nodes[badDealer], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("complaint failed form+sig verification: %v", err)
	}
	ok, err := f.RecheckReshare(dir, c, pts, th)
	if err != nil || !ok {
		t.Fatalf("RecheckReshare should justify the malformed re-share: ok=%v err=%v", ok, err)
	}

	// Negative: an HONEST dealer's re-share is NOT justified as a fault.
	honest := deals[0]
	honestFault := &ReshareFault{Dealer: 0, Shares: honest.Shares, Nonce: honest.Nonce, Commit: honest.Commit}
	honestFault.Sig = sign(t, keys[0], honest.Commit)
	hc, _ := NewReshareComplaint(honestFault, session, nodes[0], nodes[1], keys[1])
	ok2, err := f.RecheckReshare(dir, hc, pts, th)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("RecheckReshare falsely justified an honest re-share")
	}
}

// TestOpen_EquivocationDetectedAndBlamed: closer (c). An honest open is clean and
// reconstructs the value; a party that reveals a share different from the one it
// committed is named by the binding (OpeningFault), and the complaint verifies.
func TestOpen_EquivocationDetectedAndBlamed(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	keys, nodes, dir := ids(t, n)
	session := [32]byte{0x0B}

	secret := Elem(7654321)
	shares, _ := f.ShareScalar(secret, pts, th, rand.Reader)

	// Honest commit-then-open: every party commits to its true share.
	reveals := make([]*OpeningReveal, n)
	for i := 0; i < n; i++ {
		r, err := DealOpening(shares[i], rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r.Party = i
		reveals[i] = r
	}
	val, faults, clean, err := f.IdentifiableOpen(reveals, pts, th)
	if err != nil || !clean || len(faults) != 0 {
		t.Fatalf("honest open: clean=%v faults=%v err=%v", clean, faults, err)
	}
	if val != secret {
		t.Fatalf("honest open value: got %d want %d", val, secret)
	}

	// Equivocation: party 3 keeps its committed digest but reveals a swapped share.
	const cheat = 3
	reveals[cheat].Share = f.Add(reveals[cheat].Share, 99)
	reveals[cheat].Sig = sign(t, keys[cheat], reveals[cheat].Commit)
	_, faults, clean, err = f.IdentifiableOpen(reveals, pts, th)
	if err != nil {
		t.Fatal(err)
	}
	if clean || len(faults) != 1 || faults[0].Party != cheat {
		t.Fatalf("expected OpeningFault on party %d, got clean=%v faults=%v", cheat, clean, faults)
	}
	c, err := NewOpeningComplaint(faults[0], session, nodes[cheat], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("opening complaint form+sig: %v", err)
	}
	ok, err := RecheckOpening(dir, c)
	if err != nil || !ok {
		t.Fatalf("RecheckOpening should justify the equivocation: ok=%v err=%v", ok, err)
	}
}

// TestBitCheck_NonBitDetectedAndBlamed: closer (b). All-valid bits pass; a party
// contributing the value 2 (a non-bit) is caught by the batched b·(b-1)=0 proof
// and named; the complaint verifies and a genuine bit is never falsely blamed.
func TestBitCheck_NonBitDetectedAndBlamed(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	pts := evalPoints(n)
	keys, nodes, dir := ids(t, n)
	session := [32]byte{0xB1}

	mkBits := func() []*CommittedBit {
		bits := make([]*CommittedBit, n)
		for i := 0; i < n; i++ {
			b, err := f.DealBit(i%2 == 0, pts, th, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bits[i] = b
		}
		return bits
	}

	// All valid.
	ok, fault, err := f.BatchedBitCheck(mkBits(), pts, th, rand.Reader)
	if err != nil || !ok || fault != nil {
		t.Fatalf("all-valid batch: ok=%v fault=%v err=%v", ok, fault, err)
	}

	// Inject a non-bit: party 1 shares the value 2.
	bits := mkBits()
	const cheat = 1
	badShares, _ := f.ShareScalar(2, pts, th, rand.Reader)
	nonce, _ := NewNonce(rand.Reader)
	bits[cheat] = &CommittedBit{Shares: badShares, Nonce: nonce, Commit: CommitBit(badShares, nonce)}

	ok, fault, err = f.BatchedBitCheck(bits, pts, th, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ok || fault == nil || fault.Party != cheat {
		t.Fatalf("expected BitFault on party %d, got ok=%v fault=%+v", cheat, ok, fault)
	}
	fault.Sig = sign(t, keys[cheat], fault.Commit)
	c, err := NewBitComplaint(fault, session, nodes[cheat], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("bit complaint form+sig: %v", err)
	}
	just, err := f.RecheckBit(dir, c, pts, th)
	if err != nil || !just {
		t.Fatalf("RecheckBit should justify the non-bit: just=%v err=%v", just, err)
	}

	// Negative: a genuine bit is NOT justified as a non-bit.
	good, _ := f.DealBit(true, pts, th, rand.Reader)
	goodFault := &BitFault{Party: 2, Shares: good.Shares, Nonce: good.Nonce, Commit: good.Commit, Sig: sign(t, keys[2], good.Commit)}
	gc, _ := NewBitComplaint(goodFault, session, nodes[2], nodes[0], keys[0])
	just2, err := f.RecheckBit(dir, gc, pts, th)
	if err != nil {
		t.Fatal(err)
	}
	if just2 {
		t.Fatal("RecheckBit falsely justified a genuine bit as a non-bit")
	}
}
