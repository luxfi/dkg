// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package transcript is the canonical networked-MPC transcript layer for
// luxfi/dkg: a byte-stable record that every honest party recomputes
// identically, plus the SP 800-185 hash primitives every DKG round routes
// through. The TranscriptHash is the value the chain commits to in order to
// ratify a key era — so its encoding must be unambiguous (TupleHash framing)
// and its primitives must be the NIST reference ones (cSHAKE256 / KMAC256),
// not ad-hoc stdlib hashing.
//
// All hashing in luxfi/dkg routes through this file. The SP 800-185 encoders
// and the cSHAKE256/KMAC256 wrappers are ported verbatim from the pulsar
// reference (pulsar/transcript.go), which is KAT-pinned against NIST cSHAKE
// Sample #3 and KMAC256 Sample #4–6.
package transcript

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// CShake256 returns the first outLen bytes of cSHAKE256(input, N, S) per
// SP 800-185 §3, where N is the function-name and S the customization string.
// With N == "" and S == "" this degrades to plain SHAKE256, per the standard.
func CShake256(input []byte, outLen int, funcName, customization string) []byte {
	h := sha3.NewCShake256([]byte(funcName), []byte(customization))
	_, _ = h.Write(input)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// KMAC256 returns KMAC256(key, msg, outLen, S) per SP 800-185 §4:
//
//	KMAC256(K,X,L,S) = cSHAKE256(bytepad(encode_string(K),136) || X ||
//	                             right_encode(L), L, "KMAC", S)
//
// 136 = SHA-3-256 rate in bytes = (1600 - 2·256)/8.
func KMAC256(key, msg []byte, outLen int, customization string) []byte {
	preamble := bytepad(encodeString(key), 136)
	body := append(append([]byte{}, preamble...), msg...)
	body = append(body, rightEncode(uint64(outLen)*8)...)
	h := sha3.NewCShake256([]byte("KMAC"), []byte(customization))
	_, _ = h.Write(body)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// LeftEncode returns left_encode(x) per SP 800-185 §2.3.1. Operates on the BIT
// length: callers encoding a byte length pre-multiply by 8.
func LeftEncode(x uint64) []byte { return leftEncode(x) }

func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// rightEncode returns right_encode(x) per SP 800-185 §2.3.1.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00, 0x01}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, buf[i:]...)
	out = append(out, byte(8-i))
	return out
}

// encodeString returns encode_string(s) = left_encode(bit_len(s)) || s.
func encodeString(s []byte) []byte {
	out := leftEncode(uint64(len(s)) * 8)
	return append(out, s...)
}

// bytepad returns bytepad(x, w) = left_encode(w) || x || pad-to-multiple-of-w.
func bytepad(x []byte, w int) []byte {
	prefix := leftEncode(uint64(w))
	out := make([]byte, 0, len(prefix)+len(x)+w)
	out = append(out, prefix...)
	out = append(out, x...)
	for len(out)%w != 0 {
		out = append(out, 0x00)
	}
	return out
}
