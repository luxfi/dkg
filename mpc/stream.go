// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpc

import "golang.org/x/crypto/sha3"

// stream.go — a domain-separated cSHAKE256 byte stream. Used to (1) expand a
// Fiat-Shamir transcript hash into field elements (the bit-check challenge), and
// (2) give each independent CSCP coefficient its own reproducible, race-free
// randomness source derived from one master seed. It is an io.Reader so the
// field samplers (Field.Rand, RandBit) drive it directly.

// CShakeReader is an unbounded cSHAKE256 output stream keyed by a function name,
// a customization domain, and a seed. Reproducible: the same (funcName,
// customization, seed) yields the same bytes, so a committee run is KAT-stable
// and parallel workers never share state.
type CShakeReader struct {
	h sha3.ShakeHash
}

// NewCShakeReader builds a cSHAKE256 stream over (funcName, customization, seed).
func NewCShakeReader(funcName, customization string, seed []byte) *CShakeReader {
	h := sha3.NewCShake256([]byte(funcName), []byte(customization))
	_, _ = h.Write(seed)
	return &CShakeReader{h: h}
}

// Read fills p with stream bytes; it never returns an error (cSHAKE is
// unbounded).
func (r *CShakeReader) Read(p []byte) (int, error) { return r.h.Read(p) }
