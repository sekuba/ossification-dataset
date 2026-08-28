# Ossification Dataset

An auditable dataset of EVM exploits: code age at failure, reset by code or
causal critical-state changes, and loss, all measured onchain. L2BEAT consumes
the generated release to present an ossification score.

`METHODOLOGY.md` defines the cohort, the measurements, and how the curve is
built. `CONTRIBUTING.md` is the workflow for adding a record.

## Layout

```text
incidents/<chainId>/<exploitTx>.json  source records, id eip155:<chainId>:<exploitTx>
schema/incident.schema.json           source schema
schema/release-*.schema.json          generated-interface schemas
research/candidates.json              discovery-lead coverage ledger
research/raw/                         discovery inputs: seed inventory, DFHL coverage, web list, adjudications
dist/latest/incidents.json            reviewed incidents: summary and loss
dist/latest/curve.json                curve observations and exclusions
dist/latest/manifest.json             cohort rules, counts, and source hashes
scripts/check.mjs                     schema and cross-record validation
scripts/verify.mjs                    fail-closed onchain anchor verification
scripts/enrich.mjs                    mechanical anchor and code-hash enrichment
scripts/build.mjs                     deterministic distribution builder
scripts/build-candidates.mjs          deterministic research-ledger builder
```

## Consuming the release

Each curve observation carries `codeAgeSeconds` and `ageResetKind`, and resolves
its incident-level summary and loss through `incidentId` in
`dist/latest/incidents.json`. That file lists **reviewed incidents only** —
evidence, targets, verification and the unreviewed backlog stay in
`incidents/` and are hashed in the manifest, so a published figure is never a
row nobody has checked. An incident that contributes several
observations owns one loss, so aggregate per `incidentId` rather than summing
per observation. `ageKnots` is the sorted age of every selected observation.

Every admitted target appears in `dist/latest/curve.json` as selected,
deduplicated, provisional, or otherwise excluded, each with its
`exclusionReasons` — use those to pick work by missing claim rather than by file
order. `dist/latest/manifest.json` publishes the cohort rules, counts, and
source hashes for the release.

## Commands

Node 22.

```bash
npm test                                              # validate everything
npm run build                                         # regenerate dist/latest
npm run candidates                                    # regenerate the ledger
npm run verify -- incidents/1/<file>.json --curve-ready
npm run verify -- --all --quiet
npm run enrich -- --all
```

The verifier succeeds when every declared anchor reaches `PASS_ANCHORS`;
`--allow-incomplete` retains partial results for exploratory sweeps.
