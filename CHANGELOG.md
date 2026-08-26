# Changelog

## v2 — evidence-first redesign (unreleased)

V2 defines a new incident-and-target interface for audited code age and loss.

- Replaced protocol buckets with one stable incident per
  `eip155:<chainId>:<exploitTx>`.
- Assigned classification and loss to incidents and code age to independent
  targets.
- Distinguished execution context from defect-bearing code artifacts, and aged
  shared code from artifact activation, so a clone instantiated after the
  template was wired in does not reset the age.
- Added exact transaction ordering, typed code-change mechanisms, runtime
  hashes, creator evidence, and claim-addressed sources.
- Split incident review from target verification, and restricted curve
  admission to reviewed executable-code observations.
- Collapsed sibling instances of one template into a single curve observation,
  then byte-identical artifacts across incidents.
- Added a reproducible candidate ledger, resolved by a declared `discovery`
  link from an incident to the leads it answers, and a deterministic release
  manifest.
- Narrowed legacy category auto-exclusion to causes outside executed EVM code;
  oracle, economic and governance mechanism labels await the boundary test.
- Added named, timestamped review attestations and RPC-backed mechanical anchor
  enrichment.
- Pinned the production discovery cohort to complete source inventories through
  July 2026.
- Located analytical scoring and model policy in downstream consumers.

`research/raw/legacy-v1.json` is the hashed migration input.
