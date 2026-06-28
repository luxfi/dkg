# luxfi/dkg — Phase 1 foundation handoff

Phase 1 (this delivery) is the dealerless DKG foundation + 6 of the 9 malicious-
hardening components, built standalone. Phase 2 (a separate agent) builds the
malicious-secure `mpc/`, `cscp/`, `nonce/`, and `safety/` on these seams. Phase 3
wires corona + pulsar onto the library. This file names the exact seams Phase 2
plugs into — nothing here is a stub; every seam is a live, tested API.

## What Phase 1 delivers

| Package | Concern | Hardening components |
|---|---|---|
| `ring/` | R_q substrate, `Profile` (one place per scheme), FIPS-204 Power2Round/Decompose | — |
| `transcript/` | byte-stable MPC transcript, SP 800-185 cSHAKE256/KMAC256 | **2** (networked MPC transcript) |
| `channel/` | ML-KEM-768 sealed + ML-DSA-65 signed; share-only envelopes; commit-then-reveal | **3** (authenticated channels), **8** (last-mover bias) |
| `vss/` | no-reconstruct Pedersen-VSS DKG, generic over `ring.Profile` | **5** (equivocation gate), **6** (malformed-share rejection) |
| `blame/` | signed complaints, selective-abort adjudication | **4** (complaint/blame), **7** (selective-abort) |

Deferred to Phase 2: **1** (malicious CSCP), **9** (robust nonce lifecycle), plus
the `mpc/` malicious BGW substrate and the `safety/` theorem.

## Hard invariants proven (do not regress)

- **No-reconstruct.** `vss/` never forms s1, u, or a seed. Enforced by
  `vss.TestNoReconstruct_SourceStructural` (go/ast scan: no `reconstruct`/
  `lagrange`/`interpolate`/`modinverse`/`keyfromseed`/`combineshares` defined or
  called in non-test source) + `TestNoReconstruct_Runtime`. **Any reconstruction
  Phase 2 needs (e.g. a signer's Lagrange combine) lives in the consumer or a
  clearly-separate package, NEVER in `vss/`'s output path.**
- **Ring fidelity.** `vss.TestMLDSA_RingFidelity_Schoolbook` pins the lattice
  multiply to an independent schoolbook convolution over q=8380417 and the
  Ringtail q. The group commit `T` is the TRUE `A·s1+B·u` (no Montgomery R
  scaling — see `ring.ConvertVecFromNTT`, which is INTT-only by design; an
  IMForm there injects a spurious R^{-1}).
- **FIPS-204 key map.** `vss.TestMLDSA_KeyFinalize_FIPSIdentity`: ML-DSA t1 =
  Power2Round(T), reconstruction identity `T = t1·2^13 + t0`, 10-bit width.

## Seams for Phase 2

### `mpc/` — malicious-secure BGW substrate
Plugs onto **`ring/` + `vss/party.go`**.
- Build secure-mult / shared-random-bits over `ring.Profile` (use
  `ring.MatVecMul`, `ring.ScalarMulVec`, `ring.VecAdd`, the samplers).
- The malicious layer = **Feldman/Pedersen-committed re-shares with verified
  openings**. The Pedersen commit+verify primitive already exists and is
  factored: reuse `vss.computeCommits` / `vss.verifyPedersen` shapes (currently
  unexported in `vss/party.go`; promote to a shared `pedersen` helper or call
  through a thin exported wrapper — they are pure functions of `*ring.Profile`).
  Every re-share carries a commit; receivers check the degree-(T−1) Pedersen
  identity before use — identical structure to `vss.Party.Round3`.
- Re-share fault → feed a `vss.VerifyFault`-shaped value into the blame bridge
  (`vss.NewBadDeliveryComplaint`) so a bad re-share is identifiably aborted by
  the SAME complaint machinery.

### `cscp/` — malicious-secure CarryCompare (TALUS Phase B)
Plugs onto **`mpc/` (committed BGW) + `ring.HighBitsVec`**.
- `ring.HighBitsVec(r, T, gamma2)` and `ring.Decompose` are the FIPS-204
  boundary the secure comparison must realize WITHOUT any node forming w0/w.
  `cscp/` computes HighBits over committed shares; the in-the-clear
  `ring.HighBitsVec` is the test ORACLE it must match on all residues
  (gamma2 = 261888 for ML-DSA-65/87).
- The three semi-honest deviations to close (inconsistent re-share, non-{0,1}
  random bit, equivocated mask open) each map to a `mpc/` committed-opening
  check; a failure becomes a `blame.Complaint` (reuse `blame.ReasonBadDelivery`
  or add a `ReasonCSCP*` — the `blame` reason set is the extension point).

### `nonce/` — robust nonce-ticket lifecycle
Plugs onto **`transcript/` + `channel/`**.
- Bind each ticket to `(epoch, committee, policy, digest)` via a
  `transcript.Transcript` (Append the four, take `Hash()` as the ticket's
  replay-bound id). `transcript.New()`/`NewWithDomain` is the binding seam.
- Consume-once / expiry state is authenticated with `channel.Sign` /
  `channel.Verify` under a new context tag (add `CtxNonce` alongside
  `channel.CtxBroadcast`/`CtxComplaint`).

### `safety/` — abort-or-blame-not-leak theorem
Plugs onto **`blame/` + the property tests**.
- The single source of truth `AssessMalicious` descriptor enumerates each
  deviation and its resolution (detected+blamed via a `blame.Complaint`, OR
  downstream-rejected). The `blame` complaint set + `vss.RecheckBadDelivery`
  (public re-check) are the evidence the theorem quantifies over.
- Property tests: for every injected deviation, assert the outcome is a
  `blame.Complaint` that `Complaint.Verify` + the vss re-check accept, OR a
  liveness fault (retry) — NEVER a key leak or a forged signature.

## Extension points (stable API, build against these)

- **New scheme** → a new `*ring.Profile` (see `ring.Ringtail()`,
  `ring.MLDSA65()`). Never bolt onto an existing one.
- **ExpandA(rho) binding** (Phase 3 pulsar) → `Profile.WithMatrices(A, B)` with
  A = ExpandA(rho) over FIPS-204's own NTT. The DKG is identical either way;
  this is how a deployment gets a chain-genesis-seed-bound public matrix.
- **Signer consumes** `vss.ShareResult{Share, Blind, GroupKey}` and
  `ring.GroupPublicKey{T, Finalized, Aux}` (Aux = ML-DSA t0 for the hint path).
- **Malicious detection → blame** via `vss.VerifyFault` →
  `vss.NewBadDeliveryComplaint` → `blame.Complaint`.

## Phase 3 wiring notes (corona / pulsar)

- The Ringtail profile uses corona's exact NUMS tags (`corona.dkg2.A.v1`), but
  the library's group key is the **true** `A·s1+B·u` (INTT-only). corona's
  current internal convention (`ConvertVectorFromNTT` = IMForm+INTT) yields an
  R^{-1}-scaled value; the refactor must adopt the library's true convention (or
  the corona verifier already absorbs the scaling — confirm against corona's
  group-key KAT before cutover).
- pulsar's `mldsa_lattice.go` self-contained `poly[256]uint32` arithmetic is
  REPLACED by `ring/` at q=8380417; its `transcript.go` by `transcript/`; its
  `identity.go` envelope by `channel/` (which fixes the v0.1 contribution leak —
  do not re-introduce a contribution field). The TALUS signer
  (`distributed_bcc.go`) consumes the `vss` share output unchanged.

## Stock-circl signature: the documented obstruction

A stock `circl mldsa65.Verify`-passing **signature** from the no-reconstruct
group key is NOT a Phase-1 deliverable and is NOT faked. `T = A·s1+B·u` has a
large `s2 = B·u` (M-LWE-indistinguishable from χ_η but not itself small), so the
standard FIPS-204 signing algorithm does not apply unchanged — the TALUS signer's
carry elimination (Phase 2) produces the stock-verifiable signature
(output-interchangeability is a SIGNER theorem, `proofs/pulsar`). Phase 1 proves
the ring + key-map fidelity the signer stands on, plus a stock-circl
keygen→sign→verify liveness round-trip (`vss.TestMLDSA_StockCircl_Liveness`).

## Build

```
export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
go build ./... && go test ./... -count=1 -race && go vet ./...
```

All green, race-clean, vet-clean at v0.1.0.
