// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package safety

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/luxfi/dkg/blame"
	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/cscp"
	"github.com/luxfi/dkg/mpc"
	"github.com/luxfi/dkg/ring"
	"github.com/luxfi/dkg/vss"
)

// genVSSBadDelivery runs a real no-reconstruct DKG up to one recipient's Round3
// with the badDealer's delivered share corrupted, returning the resulting
// VerifyFault (a genuine Pedersen-identity failure, not a hand-built one).
func genVSSBadDelivery(t *testing.T, profile *ring.Profile, n, th int, keys []*channel.IdentityKey, nodes []channel.NodeID, dir channel.IdentityDirectory, ctx [32]byte, badDealer int) *vss.VerifyFault {
	t.Helper()
	parties := make([]*vss.Party, n)
	for i := 0; i < n; i++ {
		p, err := vss.NewParty(profile, nodes[i], keys[i], i, n, th, nodes, dir, ctx)
		if err != nil {
			t.Fatal(err)
		}
		parties[i] = p
	}
	r1 := make([]*vss.Round1Out, n)
	for i := 0; i < n; i++ {
		out, err := parties[i].Round1(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r1[i] = out
	}
	// Recipient 0 opens every dealer's share; corrupt the badDealer's.
	inputs := make(map[int]*vss.DealerInput, n)
	for i := 0; i < n; i++ {
		share, blind, err := parties[0].OpenDealerShare(i, r1[i].Envelopes[0])
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = &vss.DealerInput{Commits: r1[i].Commits, Share: share, Blind: blind}
	}
	q := profile.Ring.Q()
	inputs[badDealer].Share[0].Coeffs[0][0] = (inputs[badDealer].Share[0].Coeffs[0][0] + 1) % q
	_, fault, _ := parties[0].Round3(inputs)
	if fault == nil {
		t.Fatal("corrupted DKG share did not produce a VerifyFault")
	}
	if fault.DealerIndex != badDealer {
		t.Fatalf("fault names dealer %d, want %d", fault.DealerIndex, badDealer)
	}
	return fault
}

// vecEqual reports whether two ring vectors are coefficient-identical.
func vecEqual(a, b ring.Vector) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		for c := range a[i].Coeffs[0] {
			if a[i].Coeffs[0][c] != b[i].Coeffs[0][c] {
				return false
			}
		}
	}
	return true
}

const mldsaQ = 8380417

func evalPoints(n int) []mpc.Elem {
	pts := make([]mpc.Elem, n)
	for i := range pts {
		pts[i] = mpc.Elem(i + 1)
	}
	return pts
}

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

func sign(t *testing.T, k *channel.IdentityKey, commit []byte) []byte {
	t.Helper()
	sig, err := channel.Sign(k, channel.CtxBroadcast, commit)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func u64(v mpc.Elem) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// TestTheorem_DegreeAttack_BlamedAndSafe: closer (a). A malformed-degree
// committed re-share is detected, attributed via the Adjudicator, and the
// outcome is Safe (blamed, no leak, no forge).
func TestTheorem_DegreeAttack_BlamedAndSafe(t *testing.T) {
	f, _ := mpc.NewField(mldsaQ)
	const n, th, bad = 5, 3, 2
	keys, nodes, dir := ids(t, n)
	pts := evalPoints(n)
	adj := &Adjudicator{Field: f, EvalPoints: pts, Threshold: th, Dir: dir}

	// Dealer `bad` commits to an off-codeword re-share.
	shares, _ := f.ShareScalar(42, pts, th, rand.Reader)
	shares[4] = f.Add(shares[4], 9) // off the degree-(th-1) polynomial
	nonce, _ := mpc.NewNonce(rand.Reader)
	fault := &mpc.ReshareFault{
		Dealer: bad, Shares: shares, Nonce: nonce, Commit: mpc.CommitReshare(shares, nonce),
	}
	fault.Sig = sign(t, keys[bad], fault.Commit)
	c, err := mpc.NewReshareComplaint(fault, [32]byte{1}, nodes[bad], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	just, err := adj.Recheck(c)
	if err != nil || !just {
		t.Fatalf("Adjudicator should justify the degree attack: just=%v err=%v", just, err)
	}
	o := Outcome{Blamed: true}
	if !o.Safe() || !o.Resolved() {
		t.Fatalf("degree-attack outcome not safe/resolved: %+v", o)
	}
}

// TestTheorem_ValueAttack_LivenessFaultAndSafe: the floor. A "wrong value, right
// degree" re-share passes EVERY closer (the degree check sees a valid codeword)
// yet yields a wrong product; the ReleaseGate refuses it — a liveness fault, not
// a forgery. This is the closer-independent floor catching what attribution does
// not.
func TestTheorem_ValueAttack_LivenessFaultAndSafe(t *testing.T) {
	f, _ := mpc.NewField(mldsaQ)
	const n, th, bad = 5, 3, 2
	pts := evalPoints(n)
	x, y := mpc.Elem(123456), mpc.Elem(654321)
	xs, _ := f.ShareScalar(x, pts, th, rand.Reader)
	ys, _ := f.ShareScalar(y, pts, th, rand.Reader)

	deals := make([]*mpc.ReshareDeal, n)
	for i := 0; i < n; i++ {
		p := f.Mul(xs[i], ys[i])
		if i == bad {
			p = f.Add(p, 7) // WRONG value, but it will be a valid-degree sharing
		}
		d, _ := f.DealReshare(p, pts, th, rand.Reader)
		deals[i] = d
	}
	zs, fault, err := f.CombineCommittedReshares(deals, pts, th)
	if err != nil {
		t.Fatal(err)
	}
	if fault != nil {
		t.Fatalf("value attack must PASS the degree closer (no fault), got %+v", fault)
	}
	got, _ := f.Reconstruct(pts[:th], zs[:th])
	want := f.Mul(x, y)
	if got == want {
		t.Fatal("value attack did not change the product (test is vacuous)")
	}

	// The floor: release only a candidate that verifies as the correct product.
	gate := ReleaseGate{Verify: func(cand []byte) bool {
		return len(cand) == 8 && binary.BigEndian.Uint64(cand) == uint64(want)
	}}
	if _, ok := gate.Release(u64(got)); ok {
		t.Fatal("FORGE: release gate accepted a wrong product")
	}
	if out, ok := gate.Release(u64(want)); !ok || binary.BigEndian.Uint64(out) != uint64(want) {
		t.Fatal("release gate rejected the correct product")
	}
	o := Outcome{LivenessFault: true}
	if !o.Safe() || !o.Resolved() {
		t.Fatalf("value-attack outcome not safe/resolved: %+v", o)
	}
}

// TestTheorem_OpenEquivocation_Blamed: closer (c), adjudicated end-to-end.
func TestTheorem_OpenEquivocation_Blamed(t *testing.T) {
	f, _ := mpc.NewField(mldsaQ)
	const n, th, cheat = 5, 3, 3
	keys, nodes, dir := ids(t, n)
	adj := &Adjudicator{Field: f, EvalPoints: evalPoints(n), Threshold: th, Dir: dir}

	share := mpc.Elem(99999)
	r, _ := mpc.DealOpening(share, rand.Reader)
	r.Share = f.Add(r.Share, 5) // reveal ≠ committed digest
	r.Sig = sign(t, keys[cheat], r.Commit)
	fault := &mpc.OpeningFault{Party: cheat, Share: r.Share, Nonce: r.Nonce, Commit: r.Commit, Sig: r.Sig}
	c, _ := mpc.NewOpeningComplaint(fault, [32]byte{2}, nodes[cheat], nodes[0], keys[0])
	just, err := adj.Recheck(c)
	if err != nil || !just {
		t.Fatalf("Adjudicator should justify the open equivocation: just=%v err=%v", just, err)
	}
}

// TestTheorem_BitAttack_Blamed: closer (b), adjudicated end-to-end.
func TestTheorem_BitAttack_Blamed(t *testing.T) {
	f, _ := mpc.NewField(mldsaQ)
	const n, th, cheat = 5, 3, 1
	keys, nodes, dir := ids(t, n)
	pts := evalPoints(n)
	adj := &Adjudicator{Field: f, EvalPoints: pts, Threshold: th, Dir: dir}

	shares, _ := f.ShareScalar(2, pts, th, rand.Reader) // a non-bit
	nonce, _ := mpc.NewNonce(rand.Reader)
	fault := &mpc.BitFault{Party: cheat, Shares: shares, Nonce: nonce, Commit: mpc.CommitBit(shares, nonce)}
	fault.Sig = sign(t, keys[cheat], fault.Commit)
	c, _ := mpc.NewBitComplaint(fault, [32]byte{3}, nodes[cheat], nodes[0], keys[0])
	just, err := adj.Recheck(c)
	if err != nil || !just {
		t.Fatalf("Adjudicator should justify the bit attack: just=%v err=%v", just, err)
	}
}

// TestTheorem_DKGBadDelivery_Blamed: the cross-layer tie-in — a GENUINE vss
// no-reconstruct DKG share fault, routed by the Adjudicator to
// vss.RecheckBadDelivery. This is where safety/ consumes the vss re-check.
func TestTheorem_DKGBadDelivery_Blamed(t *testing.T) {
	profile, err := ring.MLDSA65()
	if err != nil {
		t.Fatal(err)
	}
	const n, th, badDealer = 4, 2, 1
	keys, nodes, dir := ids(t, n)
	ctx := [32]byte{0x5A}

	fault := genVSSBadDelivery(t, profile, n, th, keys, nodes, dir, ctx, badDealer)
	c, err := vss.NewBadDeliveryComplaint(profile, fault, [32]byte{4}, nodes[badDealer], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	adj := &Adjudicator{Profile: profile, Dir: dir}
	just, err := adj.Recheck(c)
	if err != nil || !just {
		t.Fatalf("Adjudicator should justify the DKG bad-delivery via vss: just=%v err=%v", just, err)
	}
}

// TestHonest_CleanNoLeak: positive control. An honest CSCP run releases the
// correct output and leaks nothing (Recorder.OtherCt == 0).
func TestHonest_CleanNoLeak(t *testing.T) {
	r, err := ring.New(3, mldsaQ) // N = 8
	if err != nil {
		t.Fatal(err)
	}
	prof := &ring.Profile{Name: "safety-test", Ring: r, K: 2, L: 1}
	f, _ := mpc.NewField(mldsaQ)
	const n, th = 5, 3
	N, K := prof.Ring.N(), prof.K

	commitShares := make([]ring.Vector, n)
	sum := ring.NewVec(prof.Ring, K)
	for i := 0; i < n; i++ {
		v := ring.NewVec(prof.Ring, K)
		for k := 0; k < K; k++ {
			for j := 0; j < N; j++ {
				x, _ := f.Rand(rand.Reader)
				v[k].Coeffs[0][j] = uint64(x)
				sum[k].Coeffs[0][j] = uint64(f.Add(mpc.Elem(sum[k].Coeffs[0][j]), x))
			}
		}
		commitShares[i] = v
	}
	want := ring.HighBitsVec(prof.Ring, sum, cscp.MLDSAGamma2)
	rec := &cscp.Recorder{}
	got, res, err := cscp.SecureHighBitsVec(prof, cscp.MLDSAGamma2, commitShares, evalPoints(n), th, rand.Reader, rec)
	if err != nil {
		t.Fatalf("honest CSCP: %v (res=%+v)", err, res)
	}
	if rec.OtherCt != 0 {
		t.Fatalf("LEAK: OtherCt=%d", rec.OtherCt)
	}
	// Release gate accepts the correct vector, rejects a corrupted one.
	gate := ReleaseGate{Verify: func(cand []byte) bool { return cand[0] == 1 }}
	correct := vecEqual(got, want)
	o := Outcome{Clean: correct}
	if !correct {
		t.Fatal("honest CSCP output != oracle")
	}
	if _, ok := gate.Release([]byte{1}); !ok {
		t.Fatal("gate rejected honest output")
	}
	if !o.Safe() || !o.Resolved() {
		t.Fatalf("honest outcome not safe/clean: %+v", o)
	}
}

// TestAssessMalicious_Descriptor checks the single-source-of-truth descriptor is
// internally consistent with the closers actually wired: every CSCP/DKG
// attribution deviation carries the blame.Reason its closer mints, the floor-only
// deviation carries no reason, and the honest-majority bound is computed right.
func TestAssessMalicious_Descriptor(t *testing.T) {
	a := AssessMalicious(3, 5) // 5 >= 2*3-1
	if !a.HonestMajority || !a.AbortOrBlameNeverLeak {
		t.Fatalf("5-of-3 should be honest-majority: %+v", a)
	}
	wantReasons := map[blame.Reason]bool{
		blame.ReasonBadReshare:   true,
		blame.ReasonBadBit:       true,
		blame.ReasonBadOpening:   true,
		blame.ReasonBadDelivery:  true,
		blame.ReasonEquivocation: true,
	}
	seen := map[blame.Reason]bool{}
	floorOnly := 0
	for _, d := range a.Deviations {
		if d.Reason == 0 {
			floorOnly++
			if d.Downstream == "" {
				t.Fatalf("floor-only deviation %q must name a downstream catch", d.Name)
			}
			continue
		}
		seen[d.Reason] = true
	}
	for r := range wantReasons {
		if !seen[r] {
			t.Fatalf("descriptor missing the deviation for reason %v", r)
		}
	}
	if floorOnly != 1 {
		t.Fatalf("expected exactly one floor-only deviation, got %d", floorOnly)
	}

	// Below the honest-majority bound the theorem precondition fails.
	bad := AssessMalicious(3, 4) // 4 < 2*3-1 = 5
	if bad.HonestMajority || bad.AbortOrBlameNeverLeak {
		t.Fatalf("4-of-3 must NOT claim honest-majority: %+v", bad)
	}
}
