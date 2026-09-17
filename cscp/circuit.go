// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cscp

import (
	"slices"

	"github.com/luxfi/dkg/mpc"
)

// circuit.go — the secure HighBits circuit (FIPS-204 Decompose high part) over a
// degree-(T-1) Shamir sharing, WITHOUT any node forming w, w0, or A0. The bit
// gadgets and the boundary-count identity are factored from the pulsar reference
// talus_cscp.go (proven coefficient-exact against FIPS Decompose on all residues)
// and run over the malicious-secure session: every multiplication is committed,
// every open is binding-identified, every random bit is batch-validated.
//
// Per coefficient: additive shares {g_i} → ⟨w⟩ (committed additive→Shamir) →
// bit-decompose ⟨w⟩ by mask-open → 16-bucket boundary count → ⟨w1⟩ → open w1.

// ── shared-bit gadgets ───────────────────────────────────────────────────────

func (s *session) notBit(a []mpc.Elem) []mpc.Elem { return s.sub(s.constShare(1), a) }

// xorBit returns ⟨a⊕b⟩ = ⟨a+b−2ab⟩ (one committed multiplication).
func (s *session) xorBit(a, b []mpc.Elem) ([]mpc.Elem, error) {
	ab, err := s.mul(a, b)
	if err != nil {
		return nil, err
	}
	return s.sub(s.add(a, b), s.scalarMul(2, ab)), nil
}

// xorPubBit returns ⟨p⊕a⟩ for a PUBLIC bit p (linear: a or 1−a).
func (s *session) xorPubBit(p uint32, a []mpc.Elem) []mpc.Elem {
	if p&1 == 0 {
		return a
	}
	return s.notBit(a)
}

// andBit returns ⟨a∧b⟩ (one committed multiplication).
func (s *session) andBit(a, b []mpc.Elem) ([]mpc.Elem, error) { return s.mul(a, b) }

// bitLTPubShared returns ⟨[x < y]⟩ for PUBLIC x and shared bits yBits (LSB-first).
// MSB→LSB: at the first differing bit, x<y iff x_j=0 (so y_j=1). One mult per bit.
func (s *session) bitLTPubShared(x uint32, yBits [][]mpc.Elem) ([]mpc.Elem, error) {
	lt := s.constShare(0)
	decided := s.constShare(0)
	for j, yBit := range slices.Backward(yBits) {
		xj := (x >> uint(j)) & 1
		diff := s.xorPubBit(xj, yBit)
		nd, err := s.mul(diff, s.notBit(decided))
		if err != nil {
			return nil, err
		}
		if xj == 0 {
			lt = s.add(lt, nd)
		}
		decided = s.add(decided, nd)
	}
	return lt, nil
}

// bitLTSharedPub returns ⟨[y < x]⟩ for shared bits yBits (LSB-first) and PUBLIC x.
func (s *session) bitLTSharedPub(yBits [][]mpc.Elem, x uint32) ([]mpc.Elem, error) {
	lt := s.constShare(0)
	decided := s.constShare(0)
	for j, yBit := range slices.Backward(yBits) {
		xj := (x >> uint(j)) & 1
		diff := s.xorPubBit(xj, yBit)
		nd, err := s.mul(diff, s.notBit(decided))
		if err != nil {
			return nil, err
		}
		if xj == 1 {
			lt = s.add(lt, nd)
		}
		decided = s.add(decided, nd)
	}
	return lt, nil
}

// bitAdd computes the shared bits of s = cPub + r (cPub PUBLIC, rBits shared,
// LSB-first). Ripple carry-save adder; result has len(rBits)+1 bits.
func (s *session) bitAdd(cPub uint32, rBits [][]mpc.Elem) ([][]mpc.Elem, error) {
	L := len(rBits)
	out := make([][]mpc.Elem, L+1)
	carry := s.constShare(0)
	for j := range L {
		cj := (cPub >> uint(j)) & 1
		rj := rBits[j]
		t1 := s.xorPubBit(cj, rj)
		sj, err := s.xorBit(t1, carry)
		if err != nil {
			return nil, err
		}
		out[j] = sj
		var cjrj []mpc.Elem
		if cj == 1 {
			cjrj = rj
		} else {
			cjrj = s.constShare(0)
		}
		ct1, err := s.mul(carry, t1)
		if err != nil {
			return nil, err
		}
		carry = s.add(cjrj, ct1) // MAJ(c_j, r_j, carry)
	}
	out[L] = carry
	return out, nil
}

// bitSubBetaQ computes the shared bits of w = s − β·q (sBits shared LSB-first, β a
// shared bit, q PUBLIC). Since β·q ≤ s (β=1 only when s≥q) the result is in [0,q).
func (s *session) bitSubBetaQ(sBits [][]mpc.Elem, beta []mpc.Elem, q uint32) ([][]mpc.Elem, error) {
	L := len(sBits)
	out := make([][]mpc.Elem, L)
	borrow := s.constShare(0)
	for j := range L {
		sj := sBits[j]
		qj := (q >> uint(j)) & 1
		if qj == 1 {
			dj := beta // d_j = β·1
			t1, err := s.xorBit(sj, dj)
			if err != nil {
				return nil, err
			}
			wj, err := s.xorBit(t1, borrow)
			if err != nil {
				return nil, err
			}
			out[j] = wj
			b1, err := s.mul(s.notBit(sj), dj)
			if err != nil {
				return nil, err
			}
			b2, err := s.mul(borrow, s.notBit(t1))
			if err != nil {
				return nil, err
			}
			borrow = s.add(b1, b2)
		} else {
			wj, err := s.xorBit(sj, borrow)
			if err != nil {
				return nil, err
			}
			out[j] = wj
			nb, err := s.mul(s.notBit(sj), borrow)
			if err != nil {
				return nil, err
			}
			borrow = nb
		}
	}
	return out, nil
}

// ── bit-decomposition + secure HighBits ──────────────────────────────────────

// randomBitwise produces a shared ⟨r⟩ ∈ [0,q) uniform with KNOWN shared bits. It
// draws bitLen committed shared random bits (each batch-validated by checkBits),
// assembles ⟨r⟩ = Σ 2^j⟨r_j⟩, and rejects (opening only the leak-free validity
// bit) when r ≥ q so the accepted r is uniform over [0,q).
func (s *session) randomBitwise() ([]mpc.Elem, [][]mpc.Elem, error) {
	const maxRetry = 64
	L := s.f.BitLen()
	q := uint32(s.f.Q())
	for range maxRetry {
		bits := make([][]mpc.Elem, L)
		rShare := s.constShare(0)
		for j := range L {
			bj, err := s.randomSharedBit()
			if err != nil {
				return nil, nil, err
			}
			bits[j] = bj
			rShare = s.add(rShare, s.scalarMul(mpc.Elem(1)<<uint(j), bj))
		}
		// Validate every contributed private bit (closer b) before trusting r.
		if err := s.checkBits(); err != nil {
			return nil, nil, err
		}
		ltShare, err := s.bitLTSharedPub(bits, q)
		if err != nil {
			return nil, nil, err
		}
		valid, err := s.open(tagValid, ltShare)
		if err != nil {
			return nil, nil, err
		}
		if valid == 1 {
			return rShare, bits, nil
		}
	}
	return nil, nil, ErrRandBits
}

// bitDecompose extracts the shared bits ⟨w_0⟩..⟨w_{L−1}⟩ of a shared ⟨w⟩ ∈ [0,q)
// WITHOUT opening w: mask with ⟨r⟩ (known bits), open the uniform c=(w−r) mod q,
// reconstruct w=(c+r) mod q bitwise (carry-save add + conditional q-subtract).
func (s *session) bitDecompose(wShare []mpc.Elem) ([][]mpc.Elem, error) {
	L := s.f.BitLen()
	q := uint32(s.f.Q())
	rShare, rBits, err := s.randomBitwise()
	if err != nil {
		return nil, err
	}
	cVal, err := s.open(tagMaskC, s.sub(wShare, rShare)) // uniform mask-open
	if err != nil {
		return nil, err
	}
	sBits, err := s.bitAdd(uint32(cVal), rBits) // s = c + r, L+1 bits
	if err != nil {
		return nil, err
	}
	ltShare, err := s.bitLTSharedPub(sBits, q) // [s < q]
	if err != nil {
		return nil, err
	}
	beta := s.notBit(ltShare) // [s ≥ q]
	wBits, err := s.bitSubBetaQ(sBits, beta, q)
	if err != nil {
		return nil, err
	}
	return wBits[:L], nil
}

// secureHighBitsShared returns ⟨w1⟩ = ⟨HighBits(w)⟩ from ⟨w⟩ via the boundary-
// count identity w1 = (Σ_{k=1..16}[w > (2k−1)γ2]) mod 16. The 16 indicators reuse
// one bit-decomposition; the mod-16 fold subtracts 16·[count==16] (an AND of all
// 16 indicator bits). ⟨w⟩ and ⟨w1⟩ are never opened here.
func (s *session) secureHighBitsShared(wShare []mpc.Elem) ([]mpc.Elem, error) {
	wBits, err := s.bitDecompose(wShare)
	if err != nil {
		return nil, err
	}
	count := s.constShare(0)
	inds := make([][]mpc.Elem, buckets)
	for k := 1; k <= buckets; k++ {
		b := (2*uint32(k) - 1) * s.gamma2 // public boundary (2k−1)·γ2
		ind, err := s.bitLTPubShared(b, wBits)
		if err != nil {
			return nil, err
		}
		inds[k-1] = ind
		count = s.add(count, ind)
	}
	allOne := inds[0]
	for k := 1; k < buckets; k++ {
		allOne, err = s.andBit(allOne, inds[k])
		if err != nil {
			return nil, err
		}
	}
	return s.sub(count, s.scalarMul(mpc.Elem(buckets), allOne)), nil
}

// shareCommitCoeff is the committed additive→Shamir reshare for one coefficient:
// each party COMMITTED-re-shares its own additive part g_i[coeff] at degree T−1
// and the quorum sums the shares into a degree-(T−1) Shamir sharing ⟨w⟩ of
// w = Σ g_i mod q. ⟨w⟩ is never opened. A malformed re-share aborts (closer a).
func (s *session) shareCommitCoeff(parts []mpc.Elem) ([]mpc.Elem, error) {
	deals := make([]*mpc.ReshareDeal, s.n)
	for i := 0; i < s.n; i++ {
		d, err := s.f.DealReshare(parts[i], s.evalPoints, s.threshold, s.rng)
		if err != nil {
			return nil, err
		}
		if s.tam != nil && s.tam.reshare != nil {
			d = s.tam.reshare(i, d)
		}
		deals[i] = d
	}
	// Verify each committed re-share is a degree-(T−1) codeword before summing.
	wShare := s.constShare(0)
	for i, d := range deals {
		if !s.f.VerifyReshareDeal(d, s.evalPoints, s.threshold) {
			s.reshareFault = &mpc.ReshareFault{
				Dealer: i, EvalPoints: s.evalPoints, Threshold: s.threshold,
				Shares: d.Shares, Nonce: d.Nonce, Commit: d.Commit,
			}
			return nil, errReshare
		}
		wShare = s.add(wShare, d.Shares)
	}
	return wShare, nil
}

// secureHighBitsCoeff runs the full per-coefficient CSCP: committed additive
// shares → ⟨w⟩ → secure HighBits → opened w1. No node ever forms w, w0, or A0.
func (s *session) secureHighBitsCoeff(parts []mpc.Elem) (mpc.Elem, error) {
	wShare, err := s.shareCommitCoeff(parts)
	if err != nil {
		return 0, err
	}
	w1Share, err := s.secureHighBitsShared(wShare)
	if err != nil {
		return 0, err
	}
	return s.open(tagW1, w1Share)
}
