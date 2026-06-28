// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vss

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crypto/rand"

	"github.com/luxfi/dkg/ring"
)

// noreconstruct_test.go — the headline structural + runtime proof that the vss
// output path NEVER reconstructs the master secret. Mirrors the pulsar CSCP
// leak-free structural tests: it parses the package's own non-test source with
// go/ast (comments excluded) and fails if any function defined or called in the
// output path implements secret reconstruction.

// forbiddenIdentifiers are reconstruction primitives that must NOT appear as a
// function name or call target anywhere in the vss output path. The DKG derives
// the group key from PUBLIC commits and keeps only per-party shares; forming
// s1/u/seed is exactly what these names denote, and exactly what is forbidden.
var forbiddenIdentifiers = []string{
	"reconstruct",
	"lagrange",
	"interpolate",
	"keyfromseed",
	"combineshares",
	"recoversecret",
	"modinverse", // Lagrange-at-0 needs a field inversion; its absence is a tell
}

// TestNoReconstruct_SourceStructural parses every non-test .go file in the vss
// package and asserts no forbidden reconstruction identifier is defined or
// called. go/ast skips comments, so prose like "never reconstructing" does not
// trip the scan — only real code does.
func TestNoReconstruct_SourceStructural(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0) // 0 = no comments retained
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				checkForbidden(t, name, node.Name.Name)
			case *ast.Ident:
				checkForbidden(t, name, node.Name)
			case *ast.SelectorExpr:
				checkForbidden(t, name, node.Sel.Name)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("no source files scanned — test is vacuous")
	}
	t.Logf("scanned %d non-test source files; no reconstruction primitive present", scanned)
}

func checkForbidden(t *testing.T, file, ident string) {
	t.Helper()
	low := strings.ToLower(ident)
	for _, bad := range forbiddenIdentifiers {
		if strings.Contains(low, bad) {
			t.Errorf("%s: forbidden reconstruction identifier %q (matches %q) in the vss output path", file, ident, bad)
		}
	}
}

// TestNoReconstruct_Runtime confirms at runtime that a party retains only a
// SHARE, not the secret: no individual share equals the reconstructed s1, and
// any t-1 shares Lagrange-combine to the WRONG value (reconstruction is
// impossible below threshold). The reconstruction here is TEST-ONLY scaffolding
// to demonstrate the property; the library performs none of it.
func TestNoReconstruct_Runtime(t *testing.T) {
	p, _ := ring.Ringtail()
	n, tt := 5, 3
	ids, nodes := committee(t, n)
	res, err := RunDKG(p, n, tt, ids, nodes, [32]byte{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// True secret from t shares.
	full := []int{0, 1, 2}
	s1 := reconstruct(p.Ring, res.Shares, full, p.L)

	// No single party share equals s1 (sharing is non-trivial: s1 is masked by
	// the higher-degree coefficients).
	for idx, share := range res.Shares {
		if ring.ConstantTimeVecEqual(share, s1) == 1 {
			t.Fatalf("party %d's share equals the master secret — sharing is trivial/broken", idx)
		}
	}

	// t-1 shares cannot reconstruct: Lagrange over {0,1} (degree-1 fit through 2
	// points of a degree-2 polynomial) yields a DIFFERENT value than the true
	// s1. This is the threshold privacy property: < t shares reveal nothing.
	below := reconstruct(p.Ring, res.Shares, []int{0, 1}, p.L)
	if ring.ConstantTimeVecEqual(below, s1) == 1 {
		t.Fatal("t-1 shares reconstructed the secret — threshold broken")
	}
}
