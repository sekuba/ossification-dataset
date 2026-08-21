# Contributing incidents

This guide is self-contained: an independent researcher (or agent) following it
can produce a valid, verifiable row without any other context.

## Inclusion rule

An incident row qualifies only if ALL of these hold:

1. **USD loss.** A credible USD figure. If the loss is only stated in a non-USD asset
   ("~750 ETH"), do not invent a conversion
2. **Identifiable victim contract** — the contract containing the exploited
   flaw. Verify onchain that the victim was not
   deployed by the attacker or the attack-tx sender (public analyses sometimes
   mislabel attacker infrastructure as the "victim")
3. **Attack transaction** hash. Its block timestamp is the incident time.

## Classify the root cause

One category per row, with a one-sentence evidence `notes`:

- `code-bug` — exploitable flaw in the victim's deployed code or onchain
  configuration (logic error, missing validation, state-changing reentrancy,
  rounding, broken access control, arbitrary call, donation/exchange-rate
  inflation, uninitialized state, flawed proof/signature verification).
  **Only this category feeds the score curve.**
- `oracle-manipulation` — the victim worked as designed; the attacker
  manipulated a price it reads (spot/TWAP/LP pricing, read-only reentrancy or
  donation skewing a consumed price).
- `economic-design` — incentive/mechanism flaw with no code defect and no
  oracle.
- `governance-design` — legitimately acquired governance power (e.g.
  flash-loaned votes) executed a hostile proposal.
- `key-compromise` / `offchain-infra` — stolen keys or frontend/infra
  compromise; contracts behaved as designed. Context rows only: no
  measurement, never curve input.
- `insider-rug` — the deployer/owner drained via openly granted powers or a
  deliberate backdoor. Not a bug.

Precedents: a flash loan is a tool — classify by what it enabled.
State-changing reentrancy = code-bug; price-skewing reentrancy/donation =
oracle-manipulation.

## Measure the code age

`codeAgeSeconds` = incident time − last change of the victim's code before the
incident:

1. Incident time: block timestamp of `exploitTx`.
2. Deployment: the victim's creation transaction (Etherscan
   `getcontractcreation`). Record the creator and reject attacker-deployed
   victims (rule 2 above).
3. Last change: the latest EIP-1967 `Upgraded` event on the victim in
   [creation block, incident block], or deployment if none. Record the count
   in `upgradeEventCount` and the basis
   (`deployment (onchain)` / `last of N upgrade events (onchain)`).
4. Architectures that change without an `Upgraded` event (diamonds, module or
   route registries, beacon proxies): set
   `nonStandardUpgradeArchitecture: true`, and if a documented pre-incident
   change introduced the flaw, put its date/tx in `documentedLastChange` and
   measure from it (basis `documented change`).

`scripts/verify.mjs protocols/<slug>.json` performs steps 1–3 mechanically —
your row must reproduce.

## Add the row

1. Find or create `protocols/<slug>.json` (kebab-case protocol name; see
   `schema/protocol.schema.json` for the exact shape).
2. Fill every required field; cite provenance in `sources` (the attack tx,
   plus a post-mortem or PoC reference).
3. Validate:
   - the file parses and matches the schema,
   - `node scripts/verify.mjs protocols/<slug>.json` returns OK for the row,
   - `node scripts/build-curve.mjs` — review the knot diff it implies.

## Adding non-exploited protocols (planned)

The same per-protocol files will carry code-age/upgrade records for protocols
that were never exploited — the exposure denominator needed to turn this
numerator into a hazard rate. Schema for those records lands with that effort.
