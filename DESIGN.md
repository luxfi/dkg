# luxfi/dkg — one dealerless DKG + malicious-secure MPC library

**Decomplect law.** The Pedersen-VSS DKG, the complaint/blame protocol, equivocation
detection, the authenticated transcript, the BGW MPC substrate, and the
malicious-secure secure-comparison are **one concern**, today **duplicated and
divergent** across `corona/dkg2` (Ringtail/R-LWE) and `pulsar` (ML-DSA): Shamir in
2 corona files + 24 pulsar files, transcript in 5 + 24, identity/KEM in 3 + 16,
Pedersen in 7 + 10. That is the smell. `github.com/luxfi/dkg` holds it **once**,
**ring-parameterized**, and both schemes consume it. One way, DRY, composable,
orthogonal.

## Hard invariants (every path)
- **No-reconstruct.** No party ever forms the master seed σ, the master secret
  `s`, or the full `sk`. The group public key is derived from the **aggregated
  public Pedersen commit** `T = Σ_i C_{i,0} = A·s1 + B·u`, never from reconstructing
  a secret. Structurally enforced + test-proven (no `KeyFromSeed`/seed in the
  output path; envelopes carry only Shamir shares, never the full contribution).
- **Dealerless.** No trusted dealer anywhere. Every party contributes; the joint
  value is unbiased given ≥1 honest contributor.
- **Bad behavior ⇒ abort or blame, NEVER leakage or forgery.** Every deviation is
  caught and attributed with publicly-verifiable signed evidence, OR is downstream-
  rejected (wrong `w1` ⇒ FindHint + stock-FIPS release gate ⇒ liveness fault, retry),
  never a forged signature or a key leak. This is the library's headline theorem.

## Package layout
```
luxfi/dkg/
  ring/        Ring abstraction (R_q parameterized) — adapts luxfi/lattice/v7/ring;
               corona binds Ringtail params, pulsar binds ML-DSA (FIPS-204) params.
  transcript/  Canonical networked-MPC transcript — byte-stable record every honest
               party recomputes identically; commits TranscriptHash for the chain.
  channel/     Authenticated channels — ML-DSA-65 signed + ML-KEM-768 sealed messages
               (the identity directory). Last-mover-bias control = commit-then-reveal
               (adversary commits before seeing others; no adaptive contribution).
  vss/         Pedersen-VSS DKG (no-reconstruct). Round1 commit+deal, Round2
               equivocation gate, Round3 verify+aggregate. Generic over ring +
               a KeyFinalize callback (Ringtail β vs ML-DSA t1). Malformed-share
               rejection = the Pedersen identity check A·f(j)+B·g(j)=Σ jᵏ C_k.
  blame/       Complaint + blame protocol — identifiable abort with signed,
               publicly-verifiable evidence (equivocation, bad-delivery). Selective-
               abort handling: committee excludes the named deviator and continues /
               re-samples; the chain slashes from the evidence.
  mpc/         BGW substrate (secure mult, shared random bits) — malicious-secure via
               Feldman/Pedersen-committed re-shares with verified openings (every
               re-share carries a commitment; receivers check degree-(T−1) before use).
  cscp/        Malicious-secure CarryCompare secure-comparison (TALUS Phase B) over
               the committed BGW substrate. Closes the three semi-honest deviations:
               inconsistent re-share, non-{0,1} random bit, equivocated mask open.
  nonce/       Robust nonce-ticket lifecycle — offline preprocessing inventory,
               consume-once, expiry, replay-bound to (epoch,committee,policy,digest).
  safety/      The abort-or-blame-not-leak theorem + property tests; the malicious
               residual descriptor (AssessMalicious) as single source of truth.
```

## Consumers (parameterize, never fork)
- **corona** (Ringtail): `vss` + `blame` + `mpc` with Ringtail ring + β KeyFinalize.
  Replaces `corona/dkg2/*` + `corona/keyera/bootstrap_pedersen.go` internals.
- **pulsar** (ML-DSA): `vss` + `blame` + `mpc` + `cscp` + `nonce` with FIPS-204 ring +
  `t1` KeyFinalize. Replaces the v0.1 reconstruction `dkg.go`/`large_dkg.go` (the
  no-reconstruct v0.2 Pedersen-VSS) and lifts `talus_cscp.go` semi-honest → Phase-B
  malicious. The TALUS signer (`distributed_bcc.go`) consumes the `vss` AlgSetup/
  AlgShare output unchanged.

## The 9 malicious-hardening components (owner-specified, all in this library)
1. malicious-secure CSCP — `cscp/` over committed BGW.
2. networked MPC transcript — `transcript/`.
3. authenticated channels / signed messages — `channel/` (ML-DSA + ML-KEM).
4. complaint and blame protocol — `blame/`.
5. equivocation detection — `vss/` Round2 commit-digest gate.
6. malformed-share rejection — `vss/` Pedersen identity check.
7. selective-abort handling — `blame/` exclude-and-continue.
8. last-mover bias controls — `channel/` commit-then-reveal.
9. robust nonce-ticket lifecycle — `nonce/`.

## Proof obligations (match the existing pen-and-paper proofs, then mechanize)
- DKG-SOUND ⇒ MSIS (Pedersen binding) · DKG-PRIV ⇒ M-LWE + Shamir hiding
  (`~/work/lux/proofs/pulsar/dkg-soundness.tex`).
- output-interchangeability: `s2=B·u` M-LWE-indistinguishable from χ_η; `T`↔FIPS pk
  (`~/work/lux/proofs/pulsar/output-interchangeability.tex`).
- CSCP malicious: each of the 3 deviations ⇒ detected+blamed (VSS opening) OR
  downstream-rejected; never leak/forge (the `safety/` theorem).
