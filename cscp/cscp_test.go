// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cscp

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/dkg/channel"
	"github.com/luxfi/dkg/mpc"
	"github.com/luxfi/dkg/ring"
)

func evalPoints(n int) []mpc.Elem {
	pts := make([]mpc.Elem, n)
	for i := range pts {
		pts[i] = mpc.Elem(i + 1)
	}
	return pts
}

func mldsaField(t *testing.T) *mpc.Field {
	t.Helper()
	f, err := mpc.NewField(mldsaQ)
	if err != nil {
		t.Fatalf("NewField: %v", err)
	}
	return f
}

// ids builds n ML-DSA-65 identities (synthetic NodeIDs 1..n) + a directory.
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

// splitAdditive splits w into n additive parts in [0,q) summing to w mod q.
func splitAdditive(t *testing.T, f *mpc.Field, w mpc.Elem, n int) []mpc.Elem {
	t.Helper()
	parts := make([]mpc.Elem, n)
	acc := mpc.Elem(0)
	for i := 0; i < n-1; i++ {
		v, err := f.Rand(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		parts[i] = v
		acc = f.Add(acc, v)
	}
	parts[n-1] = f.Sub(w%mldsaQ, acc)
	return parts
}

// TestBoundaryCount_MatchesDecompose_AllResidues proves the boundary-count
// identity the circuit computes equals FIPS-204 Decompose's high part on EVERY
// residue in [0,q) for the ML-DSA-65/87 parameter set. This is the in-the-clear
// oracle the secure circuit must realise.
func TestBoundaryCount_MatchesDecompose_AllResidues(t *testing.T) {
	const g2 = MLDSAGamma2
	for w := uint32(0); w < mldsaQ; w++ {
		count := 0
		for k := 1; k <= buckets; k++ {
			if w > (2*uint32(k)-1)*g2 {
				count++
			}
		}
		got := uint32(count % buckets)
		want, _ := ring.Decompose(w, g2)
		if got != want {
			t.Fatalf("w=%d: boundary-count=%d Decompose=%d", w, got, want)
		}
	}
}

// circuitW1 runs the full malicious-secure per-coefficient circuit on the
// additive parts of a single value w and returns the opened w1.
func circuitW1(t *testing.T, f *mpc.Field, w mpc.Elem, n, th int, rec *Recorder) mpc.Elem {
	t.Helper()
	parts := splitAdditive(t, f, w, n)
	s, err := newSession(f, evalPoints(n), th, MLDSAGamma2, rand.Reader, rec, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.secureHighBitsCoeff(parts)
	if err != nil {
		t.Fatalf("secureHighBitsCoeff(w=%d): %v", w, err)
	}
	return v
}

// TestCircuit_MatchesOracle exercises the secure circuit on a spread of residues
// — bucket boundaries (where Decompose's rounding is delicate), boundary±1, and
// random values — and asserts every output equals ring.Decompose. This proves the
// committed-multiplication / mask-open / boundary-count machinery realises the
// oracle, not just the closed-form identity.
func TestCircuit_MatchesOracle(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	g2 := mpc.Elem(MLDSAGamma2)
	ws := []mpc.Elem{0, 1, g2, g2 + 1, mldsaQ - 1, mldsaQ - g2}
	for k := 1; k <= buckets; k++ { // every bucket boundary and its neighbours
		b := (2*mpc.Elem(k) - 1) * g2
		ws = append(ws, b-1, b, b+1)
	}
	for i := 0; i < 8; i++ { // random residues
		v, _ := f.Rand(rand.Reader)
		ws = append(ws, v)
	}
	for _, w := range ws {
		got := circuitW1(t, f, w, n, th, nil)
		want, _ := ring.Decompose(uint32(w%mldsaQ), MLDSAGamma2)
		if uint32(got) != want {
			t.Fatalf("circuit w=%d: got %d want %d", w, got, want)
		}
	}
}

// TestLeakFree asserts that across a circuit run only the four sanctioned values
// ever leave the shared domain (validity bit, uniform mask-open, bit-validity
// indicator, final w1) and NOTHING else — Recorder.OtherCt stays 0.
func TestLeakFree(t *testing.T) {
	f := mldsaField(t)
	const n, th = 5, 3
	rec := &Recorder{}
	v, _ := f.Rand(rand.Reader)
	_ = circuitW1(t, f, v, n, th, rec)
	if rec.OtherCt != 0 {
		t.Fatalf("leak: OtherCt=%d (expected 0)", rec.OtherCt)
	}
	if len(rec.MaskC) == 0 || len(rec.W1) == 0 || len(rec.Valid) == 0 {
		t.Fatalf("expected the sanctioned opens to be recorded: valid=%d maskC=%d w1=%d",
			len(rec.Valid), len(rec.MaskC), len(rec.W1))
	}
	// Exactly one w1 is opened per coefficient.
	if len(rec.W1) != 1 {
		t.Fatalf("expected exactly one w1 open, got %d", len(rec.W1))
	}
}

// smallProfile builds an ML-DSA-q ring with a tiny degree so the full parallel
// driver runs over few coefficients. The cscp driver only uses Ring (q, N) and K.
func smallProfile(t *testing.T) *ring.Profile {
	t.Helper()
	r, err := ring.New(3, mldsaQ) // N = 8
	if err != nil {
		t.Fatalf("ring.New: %v", err)
	}
	return &ring.Profile{Name: "cscp-test", Ring: r, K: 2, L: 1}
}

// TestDriver_VectorMatchesOracle runs the public SecureHighBitsVec over a small
// poly-vector of additive commitment shares and checks every output coefficient
// equals ring.HighBitsVec(Σ_i g_i), with the leak recorder clean.
func TestDriver_VectorMatchesOracle(t *testing.T) {
	prof := smallProfile(t)
	f := mldsaField(t)
	const n, th = 5, 3
	N := prof.Ring.N()
	K := prof.K

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
	wantVec := ring.HighBitsVec(prof.Ring, sum, MLDSAGamma2)

	rec := &Recorder{}
	got, res, err := SecureHighBitsVec(prof, MLDSAGamma2, commitShares, evalPoints(n), th, rand.Reader, rec)
	if err != nil {
		t.Fatalf("SecureHighBitsVec: %v (res=%+v)", err, res)
	}
	for k := 0; k < K; k++ {
		for j := 0; j < N; j++ {
			if got[k].Coeffs[0][j] != wantVec[k].Coeffs[0][j] {
				t.Fatalf("driver [%d][%d]: got %d want %d", k, j, got[k].Coeffs[0][j], wantVec[k].Coeffs[0][j])
			}
		}
	}
	if rec.OtherCt != 0 {
		t.Fatalf("driver leak: OtherCt=%d", rec.OtherCt)
	}
	if len(rec.W1) != K*N {
		t.Fatalf("expected %d w1 opens, got %d", K*N, len(rec.W1))
	}
}

// runDeviation runs one coefficient with a tamper injected and returns the
// session (carrying any captured fault) and the error.
func runDeviation(t *testing.T, f *mpc.Field, n, th int, tam *tamper) (*session, error) {
	t.Helper()
	w, _ := f.Rand(rand.Reader)
	parts := splitAdditive(t, f, w, n)
	s, err := newSession(f, evalPoints(n), th, MLDSAGamma2, rand.Reader, &Recorder{}, tam)
	if err != nil {
		t.Fatal(err)
	}
	_, runErr := s.secureHighBitsCoeff(parts)
	return s, runErr
}

// TestDeviation_Reshare: closer (a) inside the circuit. A dealer's committed
// re-share is forced off the degree-(T-1) code; the circuit aborts with a
// ReshareFault that becomes a verifiable ReasonBadReshare complaint.
func TestDeviation_Reshare(t *testing.T) {
	f := mldsaField(t)
	const n, th, bad = 5, 3, 2
	keys, nodes, dir := ids(t, n)
	tam := &tamper{reshare: func(dealer int, d *mpc.ReshareDeal) *mpc.ReshareDeal {
		if dealer != bad {
			return d
		}
		shares := append([]mpc.Elem(nil), d.Shares...)
		shares[4] = f.Add(shares[4], 13) // off the polynomial
		nonce, _ := mpc.NewNonce(rand.Reader)
		return &mpc.ReshareDeal{Shares: shares, Nonce: nonce, Commit: mpc.CommitReshare(shares, nonce)}
	}}
	s, runErr := runDeviation(t, f, n, th, tam)
	if runErr != errReshare || s.reshareFault == nil || s.reshareFault.Dealer != bad {
		t.Fatalf("expected reshare deviation on dealer %d: err=%v fault=%+v", bad, runErr, s.reshareFault)
	}
	s.reshareFault.Sig = sign(t, keys[bad], s.reshareFault.Commit)
	c, err := mpc.NewReshareComplaint(s.reshareFault, [32]byte{0xA}, nodes[bad], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("complaint verify: %v", err)
	}
	ok, err := f.RecheckReshare(dir, c, evalPoints(n), th)
	if err != nil || !ok {
		t.Fatalf("RecheckReshare should justify: ok=%v err=%v", ok, err)
	}
}

// TestDeviation_Open: closer (c). A party reveals a share inconsistent with its
// committed digest; the circuit names it (OpeningFault → ReasonBadOpening).
func TestDeviation_Open(t *testing.T) {
	f := mldsaField(t)
	const n, th, cheat = 5, 3, 3
	keys, nodes, dir := ids(t, n)
	tam := &tamper{open: func(party int, r *mpc.OpeningReveal) *mpc.OpeningReveal {
		if party == cheat {
			r.Share = f.Add(r.Share, 99) // keep Commit, swap the revealed share
		}
		return r
	}}
	s, runErr := runDeviation(t, f, n, th, tam)
	if runErr != errOpen || len(s.openFaults) != 1 || s.openFaults[0].Party != cheat {
		t.Fatalf("expected open deviation on party %d: err=%v faults=%+v", cheat, runErr, s.openFaults)
	}
	fault := s.openFaults[0]
	fault.Sig = sign(t, keys[cheat], fault.Commit)
	c, err := mpc.NewOpeningComplaint(fault, [32]byte{0xC}, nodes[cheat], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("complaint verify: %v", err)
	}
	ok, err := mpc.RecheckOpening(dir, c)
	if err != nil || !ok {
		t.Fatalf("RecheckOpening should justify: ok=%v err=%v", ok, err)
	}
}

// TestDeviation_Bit: closer (b). A party contributes the value 2 as a "random
// bit"; the batched b·(b−1)=0 proof catches it (BitFault → ReasonBadBit).
func TestDeviation_Bit(t *testing.T) {
	f := mldsaField(t)
	const n, th, cheat = 5, 3, 1
	keys, nodes, dir := ids(t, n)
	tam := &tamper{bit: func(party int, b *mpc.CommittedBit) *mpc.CommittedBit {
		if party != cheat {
			return b
		}
		shares, _ := f.ShareScalar(2, evalPoints(n), th, rand.Reader) // a non-bit
		nonce, _ := mpc.NewNonce(rand.Reader)
		return &mpc.CommittedBit{Shares: shares, Nonce: nonce, Commit: mpc.CommitBit(shares, nonce)}
	}}
	s, runErr := runDeviation(t, f, n, th, tam)
	if runErr != errBit || s.bitFault == nil {
		t.Fatalf("expected bit deviation: err=%v fault=%+v", runErr, s.bitFault)
	}
	// The captured bit-sharing reconstructs to the non-bit value 2.
	s.bitFault.Sig = sign(t, keys[cheat], s.bitFault.Commit)
	c, err := mpc.NewBitComplaint(s.bitFault, [32]byte{0xB}, nodes[cheat], nodes[0], keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(dir); err != nil {
		t.Fatalf("complaint verify: %v", err)
	}
	ok, err := f.RecheckBit(dir, c, evalPoints(n), th)
	if err != nil || !ok {
		t.Fatalf("RecheckBit should justify: ok=%v err=%v", ok, err)
	}
}
