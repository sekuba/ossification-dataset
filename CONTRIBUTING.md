# Contributing incidents

This guide is self-contained: an independent researcher (or agent) following it
can produce a valid, verifiable row without any other context.

## Inclusion rule

An incident row qualifies only if ALL of these hold:

1. **Loss of at least $1,000** — value stolen, or permanently locked by the
   flaw; profit to an attacker is not required. Record a high-confidence USD
   figure in `lossUsd`: USD-pegged stables at 1:1, and deep-market assets (ETH/WETH,
   BTC/WBTC, BNB/WBNB, SOL, …) converted at the incident timestamp —

   ```
   curl -s https://coins.llama.fi/prices/historical/<incidentTimestamp>/coingecko:ethereum
   ```

   citing the rate in a `curated-review` source. Keep `lossOther` (e.g.
   `"5.12M ZKP"`) for project tokens and other illiquid assets, whose price at
   the incident is itself a product of the attack; set `lossUsd` null there.
2. **Identifiable victim contract** — the contract the protocol runs at, which
   for a proxy is the proxy rather than the implementation behind it. Verify
   onchain that its creator is neither the attacker nor the attack-tx sender;
   public analyses sometimes mislabel attacker infrastructure, or an
   implementation, as the victim.
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

`codeAgeSeconds` = incident time − the last change to the victim's executing
code before the incident.

1. **Incident time**: block timestamp of `exploitTx`.
2. **Creation**: the victim's creation transaction — Etherscan
   `getcontractcreation`, or a binary search over `eth_getCode` for chains it
   does not serve (`eth_getBlockReceipts` on that block gives the creator and
   creation tx). Record the creator for rule 2.
3. **Last change** — whatever a code change means for this victim's
   construction. Best effort, in whichever way applies:
   - the latest EIP-1967 `Upgraded` event on the victim;
   - the architecture's own change event, often emitted by another contract:
     a beacon's `Upgraded`, a diamond's `DiamondCut`, an Aragon kernel's
     `SetApp`, a Compound fork's `NewImplementation`, a registry's route event;
   - the block at which the implementation or route storage slot last changed,
     found by binary-searching `eth_getStorageAt`
     (`cast storage <addr> --etherscan-api-key …` prints the named layout);
   - creation, for a victim whose code is immutable (no `DELEGATECALL` in the
     runtime and an identical codehash at the creation and incident blocks).

   Code changes when the protocol (including its secured funds) starts running it,
   not when it was compiled: measure a proxy from the upgrade that pointed it at
   an implementation, not from that implementation's own deployment.

   Record the basis: `deployment (onchain)`, `last of N upgrade events
   (onchain)`, or `documented change` — the last with the timestamp, block and
   method in `documentedLastChange` and the change history in a
   `curated-review` source. Set `nonStandardUpgradeArchitecture: true` where
   the victim can change without an EIP-1967 event.

`scripts/verify.mjs protocols/<slug>.json` re-derives steps 1–3 for standard
EIP-1967 victims; your row must reproduce. `documented change` rows report
MANUAL and stand on their cited evidence.

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
