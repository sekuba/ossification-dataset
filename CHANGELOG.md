# Changelog

## v2 — evidence-first redesign (unreleased)

V2 defines a new incident-and-target interface for audited code age and loss.

- Replaced protocol buckets with one stable incident per
  `eip155:<chainId>:<exploitTx>`.
- Assigned classification and loss to incidents and code age to independent
  targets.
- Distinguished execution context from defect-bearing code artifacts.
- Added exact transaction ordering, typed code-change mechanisms, runtime
  hashes, creator evidence, and claim-addressed sources.
- Split incident review from target verification.
- Restricted curve admission to reviewed executable-code observations.
- Grouped repeated failures by
  `(codeArtifact.codeHash, failureModeId)`.
- Added a reproducible candidate ledger and deterministic release manifest.
- Added named, timestamped review attestations for reviewed claims.
- Added deterministic target blockers and RPC-backed mechanical enrichment.
- Pinned the production discovery cohort to complete source inventories through
  July 2026.
- Located analytical scoring and model policy in downstream consumers.

`research/raw/legacy-v1.json` is the hashed migration input.
