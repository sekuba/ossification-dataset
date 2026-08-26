# Changelog

## v2 — evidence-first redesign (unreleased)

V2 defines a new incident-and-target interface for audited code age and loss.

- Replaced protocol buckets with one stable incident per
  `eip155:<chainId>:<exploitTx>`.
- Assigned the defect summary and loss to incidents and code age to
  independent targets.
- Distinguished execution context from defect-bearing code artifacts, and aged
  shared code from artifact activation, so a clone instantiated after the
  template was wired in does not reset the age.
- Added exact transaction ordering, typed age-reset mechanisms, runtime
  hashes, creator evidence, and claim-addressed sources.
- Split incident review from target verification, and restricted curve
  admission to reviewed age observations.
- Collapsed sibling instances of one template into a single curve observation,
  then byte-identical artifacts across incidents.
- Added a reproducible candidate ledger, resolved by a declared `discovery`
  link from an incident to the leads it answers, and a deterministic release
  manifest.
- Narrowed legacy category auto-exclusion to causes outside EVM code or
  persistent onchain state; mechanism labels await causal review.
- Added named, timestamped review attestations and RPC-backed mechanical anchor
  enrichment.
- Pinned the production discovery cohort to complete source inventories through
  July 2026.
- Located analytical scoring and model policy in downstream consumers.

- Published reviewed incidents only in the release; unreviewed legacy rows stay
  in `incidents/` for review rather than beside reviewed losses.
- Recorded the valuation basis in `loss.usd.method`, including
  `realised-proceeds`.
- Re-examined every minimal-proxy target under the case-by-case clone rule and
  retained clone age where instance state or assets created the exposure.
- Reset code age on a causal critical-state change, anchored by a storage write
  or reproducible view call.
- Re-examined configuration adjudications under that rule: reopened 13 persistent
  state changes for incident research while retaining direct privileged drains
  and market or governance risk as exclusions.
- Replaced exclusion-only research records with explicit adjudications so a
  rejected lead can be reopened without losing its evidence trail.
- Admitted the Yearn v1 yDAI, Rho Markets, and Moonwell cbETH configuration
  incidents after reconstructing their state resets and losses onchain;
  corrected reported loss scopes where they did not match causal depletion.
- Dropped `classification.rootCause`, a constant, and the `supports` declaration
  on sources, which restated what the per-claim references already say.

`research/raw/legacy-v1.json` is the hashed migration input.
