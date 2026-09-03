# Ossification Dataset

An auditable dataset of EVM exploits: code age at failure, reset by code or
causal critical-state changes, and loss, all measured onchain. One incident is
one fault episode, one knot, and one loss. L2BEAT consumes the generated release
to present an ossification score.

`METHODOLOGY.md` defines the cohort, the measurements, and how the curve is
built. `CONTRIBUTING.md` is the workflow for adding a record.

## Layout

```text
incidents/<chainId>/<exploitTx>.json  source records, id eip155:<chainId>:<exploitTx>
schema/incident.schema.json           source schema
schema/release-*.schema.json          generated-interface schemas
research/candidates.json              discovery-lead coverage ledger
research/raw/                         discovery inputs: seed inventory, DFHL coverage, web list, adjudications
dist/latest/incidents.json            curve rows and excluded records
dist/latest/manifest.json             cohort rules, counts, and source hashes
scripts/check.mjs                     schema and cross-record validation
scripts/verify.mjs                    fail-closed onchain anchor verification
scripts/enrich.mjs                    mechanical anchor and code-hash enrichment
scripts/build.mjs                     deterministic distribution builder
scripts/build-candidates.mjs          deterministic research-ledger builder
```

## Consuming the release

Each row of `incidents` in `dist/latest/incidents.json` is one reviewed
incident: its summary, its loss, and the `codeAgeSeconds` and `ageResetKind`
of the target that supplied the knot. Rows are sorted by age. Every other record
appears in `excluded` with its `exclusionReasons` — use those to pick work by
missing claim rather than by file order. Evidence, targets and verification stay
in `incidents/` and are hashed in `dist/latest/manifest.json`, which also
publishes the cohort rules and counts.

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
