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
- Located analytical scoring and model policy in downstream consumers.

Git history and tags retain v1, while `research/raw/legacy-v1.json` preserves its
complete migration input.
