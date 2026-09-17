// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/dkg/ring"
)

// serialize.go — byte-stable serialization of standard-form share material for
// the sealed envelope. Shares are single-level (Coeffs[0]) standard-form
// vectors, so the wire layout is simply L polys × n coefficients × little-
// endian uint64. The width is fixed by (L, n), letting the opener recover the
// exact share length without a length prefix.

var (
	errShareWire = errors.New("dkg/vss: share wire length mismatch")
)

// shareWireLen returns the byte width of a serialized (share ‖ blind) pair:
// 2 vectors × L polys × n coefficients × 8 bytes.
func shareWireLen(L, n int) int { return 2 * L * n * 8 }

// serializeShareBlind packs (share, blind) — each a length-L standard-form
// vector — into a flat little-endian uint64 byte blob for sealing.
func serializeShareBlind(share, blind ring.Vector, L, n int) []byte {
	out := make([]byte, shareWireLen(L, n))
	off := 0
	for _, v := range [2]ring.Vector{share, blind} {
		for i := range L {
			coeffs := v[i].Coeffs[0]
			for c := range n {
				binary.LittleEndian.PutUint64(out[off:], coeffs[c])
				off += 8
			}
		}
	}
	return out
}

// deserializeShareBlind reverses serializeShareBlind into two fresh length-L
// standard-form vectors over r.
func deserializeShareBlind(r *ring.Ring, wire []byte, L, n int) (share, blind ring.Vector, err error) {
	if len(wire) != shareWireLen(L, n) {
		return nil, nil, errShareWire
	}
	share = ring.NewVec(r, L)
	blind = ring.NewVec(r, L)
	off := 0
	for _, v := range [2]ring.Vector{share, blind} {
		for i := range L {
			coeffs := v[i].Coeffs[0]
			for c := range n {
				coeffs[c] = binary.LittleEndian.Uint64(wire[off:])
				off += 8
			}
		}
	}
	return share, blind, nil
}

// serializeCommits packs a dealer's commit vector list (t vectors, each R_q^K,
// plain-NTT form) into a byte-stable blob for the equivocation digest and the
// commit-then-reveal commitment. Layout: t ‖ (K ‖ n-coeff-LE-u64 per poly).
func serializeCommits(commits []ring.Vector, K, n int) []byte {
	var b4 [4]byte
	out := make([]byte, 0, 4+len(commits)*K*n*8)
	binary.BigEndian.PutUint32(b4[:], uint32(len(commits)))
	out = append(out, b4[:]...)
	for _, c := range commits {
		for i := range K {
			coeffs := c[i].Coeffs[0]
			for k := range n {
				var b8 [8]byte
				binary.LittleEndian.PutUint64(b8[:], coeffs[k])
				out = append(out, b8[:]...)
			}
		}
	}
	return out
}
