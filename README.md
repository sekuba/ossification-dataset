# Ossification Dataset

An auditable dataset of EVM code-bug exploits, the age of the executing code at
failure, and the resulting loss.

## Interface

Each file under `incidents/<chainId>/` represents one exploit transaction and
uses the stable ID `eip155:<chainId>:<exploitTx>`. The incident owns its
classification and loss. Its targets own independently measured code ages.

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
cohort admission, measurements, verification, loss valuation, and
deduplication.

## Repository layout

```text
incidents/                    source incident records
schema/incident.schema.json   source schema
schema/release-*.schema.json  generated-interface schemas
research/candidates.json      candidate disposition and coverage ledger
research/raw/                 hashed discovery and migration inputs
dist/latest/incidents.json    generated incident interface
dist/latest/curve.json        curve observations and revalidation queue
dist/latest/manifest.json     cohort, counts, and source hashes
scripts/check.mjs             schema and cross-record validation
scripts/verify.mjs            fail-closed onchain anchor verification
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
```

The verifier exits successfully when every declared anchor reaches
`PASS_ANCHORS`. Exploratory sweeps can retain incomplete results with
`--allow-incomplete`.

Interpret `ageKnots` as the empirical ages of reviewed exploit observations.
