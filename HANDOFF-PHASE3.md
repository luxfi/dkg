# luxfi/dkg — Phase 3 handoff (consumer rewire)

Phase 1 delivered the no-reconstruct DKG foundation (`ring`, `transcript`,
`channel`, `vss`, `blame`). Phase 2 (this delivery, **v0.2.0**) delivered the
malicious-secure threshold-signing MPC (`mpc`, `cscp`, `nonce`, `safety`). Phase 3
rewires corona + pulsar onto the library so the duplication ends. This file names
the exact seams — every seam is a live, tested v0.2.0 API.

## What Phase 2 delivers (build against these)

| Package | Surface | Role |
|---|---|---|
| `mpc` | `Field` (GF(q) from a `*ring.Profile`), `ShareScalar`/`Reconstruct`/`MulShares`/`SharedRandomBit` (semi-honest), `MulSharesCommitted`/`CombineCommittedReshares`/`CheckDegree` (closer a), `DealOpening`/`IdentifiableOpen` (closer c), `DealBit`/`BatchedBitCheck` (closer b), `NewReshareComplaint`/`RecheckReshare`, `NewOpeningComplaint`/`RecheckOpening`, `NewBitComplaint`/`RecheckBit` | malicious-secure BGW substrate |
| `cscp` | `SecureHighBitsVec(profile, gamma2, commitShares, evalPoints, threshold, rng, rec)` → (w1 vector, `Result`), `Recorder`, `MLDSAGamma2` | malicious-secure CarryCompare (TALUS Phase B) |
| `nonce` | `Inventory` (`Bind`/`Consume`), `Ticket`, `Binding`, `VerifyTicket`, `channel.CtxNonce` | robust one-time nonce-ticket lifecycle |
| `safety` | `AssessMalicious`, `ReleaseGate`, `Outcome`, `Adjudicator` | abort-or-blame-never-leak theorem + one adjudication authority |
| `blame` | `ReasonBadReshare`/`ReasonBadOpening`/`ReasonBadBit` + evidence builders/parsers | new identifiable-abort reasons |

## Load-bearing pins (do NOT regress in Phase 3)

1. **The MPC commitment is a cSHAKE256 hash, NOT the vss lattice Pedersen.** A BGW
   re-share over GF(q) shares a FULL-RANGE scalar; the lattice Pedersen binds only
   SHORT openings (Module-SIS), so it provides no binding here. Do not "unify" the
   two commitments — they bind different objects (short DKG contributions vs
   full-range MPC re-shares). See `mpc/committed.go` header.
2. **Identification is by commitment binding, not Reed-Solomon decoding.** At
   N = 2T−1 a T−1 coalition can out-vote the honest polynomial, so RS
   error-correction cannot name the deviator. The closers name via signed
   commitments + the exact `CheckDegree` membership test. See `mpc/openshare.go`.
3. **The boundary-count fold is ML-DSA-65/87 only** (γ2 = 261888, m = 16 buckets).
   `cscp` rejects any other γ2 (`ErrParamSet`). ML-DSA-44 (m = 44) is out of scope.
4. **INTT-only group-key convention** (carried from Phase 1): the group commit T
   is the TRUE `A·s1 + B·u`. corona's current `ConvertVectorFromNTT` is IMForm+INTT
   (R⁻¹-scaled, self-consistent in corona's own pipeline) — reconcile against
   corona's group-key KAT before cutover.

## corona (Ringtail / Module-LWE) — drop dkg2 internals

- Replace `corona/dkg2/*` and `corona/keyera/bootstrap_pedersen.go` internals with
  `vss` + `blame` + `mpc`, parameterized by `ring.Ringtail()` (K=8, L=7,
  q=0x1000000004A01, Gaussian χ, Round_Xi `KeyFinalize`, corona's exact NUMS tags).
- corona does **not** consume `cscp` (the boundary-count circuit is ML-DSA HighBits
  specific). Ringtail's β rounding is its own `KeyFinalize`; any threshold BGW it
  needs comes from `mpc` over the Ringtail field (`mpc.FieldFromProfile`).
- The group key is the **true** `A·s1 + B·u` (INTT-only); confirm corona's verifier
  absorbs (or is migrated off) its R⁻¹ scaling first (pin 4).

## pulsar (ML-DSA / FIPS-204) — drop v0.1 reconstruct, lift talus_cscp

- **DKG**: replace `dkg.go`/`large_dkg.go` (v0.1 reconstruct) with the `vss`
  no-reconstruct Pedersen-VSS over `ring.MLDSA65()` + `Profile.WithMatrices(A, B)`
  for the `ExpandA(rho)` chain-genesis binding. `t1` `KeyFinalize`.
- **CSCP**: `talus_cscp.go` (semi-honest) → `cscp.SecureHighBitsVec` (malicious).
  Pulsar's `CEFComputeW1` feeds the per-party additive commitment shares `{g_i}`
  in and takes the w1 vector out; the in-house `cefIdealSecureHighBits` /
  `cefReconstructW1FromShares` become the test oracle only (already proven equal to
  `ring.HighBitsVec`).
- **BGW**: `talus_mpc.go bgwMulShares` → `mpc.MulShares` / `mpc.MulSharesCommitted`.
- **Nonce**: the TALUS `NoncePool` lifecycle → `nonce.Inventory` (the dealerless
  nonce DKG `NonceDKGParticipant` stays in pulsar; only the consume-once / expiry /
  replay-binding lifecycle moves here). Bind to (epoch, committee, policy, digest).
- **Safety**: `AssessCSCPMalicious` → `safety.AssessMalicious`; `TalusReleaseGate`
  → `safety.ReleaseGate{Verify: stock mldsa65.Verify ∘ FindHint}`; route blame via
  `safety.Adjudicator`.
- The TALUS signer (`distributed_bcc.go`) consumes the `vss` share output unchanged.

## Honest residual carried into Phase 3 (scoped, not faked)

- **Keygen is still trusted-dealer** in pulsar (`DealAlgShares`). Dealerless KEY DKG
  is unreachable for byte-FIPS-204 (`assessDealerlessFIPS`: the joint S_η sum
  violates the BCC norm bound at N≥2). Permissionless safety rests on the dealerless
  **corona** leg in the AND-mode dual-PQ cert. The `vss` DKG produces the group key
  T = A·s1 + B·u; the stock-verifiable threshold *signature* needs the TALUS signer.
- **The "wrong value, right degree" re-share is caught by the floor, not attributed.**
  The degree/equivocation/bit closers do not catch a re-share that shares the wrong
  value at the right degree; `safety`'s `ReleaseGate` refuses the resulting wrong w1
  (liveness fault, never a forge). Identifiable attribution of THIS deviation needs
  multiplication-triple (Beaver) proofs — a precise, documented residual
  (`safety.AssessMalicious`'s floor-only deviation), out of scope for v0.2.0.

## Build

```
export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
go build ./... && go test ./... -count=1 && go test -race ./mpc/... ./cscp/...
go vet ./... && gofmt -l .
```

All green, race-clean, vet-clean, gofmt-clean at v0.2.0.
