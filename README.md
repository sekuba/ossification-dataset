# Ossification Dataset

An auditable dataset of EVM code-bug exploits, the age of the executing code at
failure, and the resulting loss. Its generated release is consumed by L2BEAT's
ossification framework to present an ossification score.

## Interface

Each file under `incidents/<chainId>/` represents one same-chain exploit
campaign, anchored to one selected defect-executing or failure-finalizing
transaction, and uses the stable ID `eip155:<chainId>:<exploitTx>`. The
incident owns its classification and non-overlapping loss. Its targets own
the target-level code ages.

A target identifies:

- the `executionAddress` whose storage and authority were used;
- the implementation, facet, module, library, or direct runtime containing the
  defect;
- the last onchain change that made that artifact active;
- evidence for artifact identity and code history.

Code age is:

```text
incident timestamp - last pre-exploit executable-code change timestamp
```

Transaction and log positions provide exact ordering. `METHODOLOGY.md` defines
the scope boundary, incident units, measurements, verification, loss
valuation, and deduplication.

## Repository layout

```text
incidents/                    source incident records
schema/incident.schema.json   source schema
schema/release-*.schema.json  generated-interface schemas
research/candidates.json      candidate disposition and coverage ledger
research/raw/                 hashed discovery and migration inputs
dist/latest/incidents.json    generated incident interface
dist/latest/curve.json        curve observations and deduplication
dist/latest/manifest.json     cohort, counts, and source hashes
scripts/check.mjs             schema and cross-record validation
scripts/verify.mjs            fail-closed onchain anchor verification
scripts/enrich.mjs            mechanical anchor and code-hash enrichment
scripts/build.mjs             deterministic distribution builder
scripts/build-candidates.mjs  deterministic research-ledger builder
```

Consumers join each curve observation to its incident-level loss through
`incidentId`. Every source target appears in the curve release as selected,
deduplicated, provisional, or otherwise excluded.

Current cohort counts, verification tiers, exclusions, and source hashes are
published in `dist/latest/manifest.json` and `dist/latest/curve.json`.

## Commands

Use Node 22.

```bash
npm test
npm run build
npm run candidates
npm run verify -- incidents/1/<file>.json
npm run verify -- --all --quiet
npm run verify -- incidents/1/<file>.json --curve-ready
npm run enrich -- --all
```

The verifier exits successfully when every declared anchor reaches
`PASS_ANCHORS`. Exploratory sweeps can retain incomplete results with
`--allow-incomplete`.

Interpret `ageKnots` as the empirical ages of reviewed exploit observations.
`dist/latest/curve.json` lists every non-selected target under
`provisionalObservations` with its `exclusionReasons`; use that to select work
by explicit missing claim rather than by file order.
