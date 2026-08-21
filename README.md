# Ossification Dataset

The exploit dataset behind L2BEAT's **ossification score**. The score of a
protocol is the interpolated percentile of its critical perimeter's age within
this dataset's exploited-code ages: *"ossification N means the unchanged
perimeter has outlived the code age of N% of recorded code-bug exploits."*

Everything here is verifiable from public onchain data: incident times are
exploit-transaction block timestamps, code ages come from contract-creation
lookups and EIP-1967 `Upgraded` logs, and `scripts/verify.mjs` re-derives any
row from an RPC and the Etherscan API.

## Layout

```
protocols/<slug>.json   one file per protocol: its incidents (later: code-age
                        records for non-exploited protocols)
curve/v<version>.json   released curve: the sorted code-age knots that define
                        the score; changes only at deliberate releases
schema/                 JSON Schema for protocol files
scripts/build-curve.mjs deterministic rebuild of the curve from protocols/
scripts/verify.mjs      re-derive one protocol's measurements onchain
```

## What a row means

Each incident carries:

- **onchain anchors**: `exploitTx` (its block timestamp is the incident time),
  `victimContract`, `chain`;
- **the measurement**: deployment timestamp, count of pre-incident `Upgraded`
  events, last-change timestamp, and `codeAgeSeconds` — the age of the
  exploited code when it was exploited — plus the evidence `basis`;
- **classification**: a root-cause `category` and a one-sentence evidence
  `notes`;
- **loss**: verified USD (USD-pegged stables at 1:1; incidents whose loss is
  only known in volatile assets are excluded rather than price-converted);
- **provenance**: post-mortems, curated review, or the DeFiHackLabs PoC file
  (pinned by commit) the row was extracted from.

Rows that failed verification stay in the dataset with their exclusion status
(`ATTACKER_DEPLOYED` — the quoted "victim" was deployed by the attacker;
`NO_CREATION_INFO`; `DEPLOY_AFTER_INCIDENT`) — they are audit trail, not curve
input.

## The curve

`scripts/build-curve.mjs` rebuilds the released knots deterministically:

- `category === "code-bug"` and `measurement.status === "OK"` only;
- one observation per `(chain, victimContract)` — repeated exploits of the
  same contract are not independent; curated rows win over registry rows,
  then the earliest incident wins;
- knots are the sorted `codeAgeSeconds`.

The score is the interpolated percentile within the knots, using Weibull
plotting positions `p_i = (i+1)/(n+1)` (so the extremes approach rather than
reach 0 and 100).

Check a release: `node scripts/build-curve.mjs --check curve/v2026-08.json`

## Categories

`code-bug` (exploitable flaw in the victim's deployed code or onchain config —
the class the score is calibrated on), `oracle-manipulation`,
`economic-design`, `governance-design`, `key-compromise`, `insider-rug`,
`offchain-infra`. Boundary precedents: state-changing reentrancy is a code
bug; read-only reentrancy or donation skewing a consumed price is oracle
manipulation; an owner draining via openly granted powers is an insider rug.

## Known limitations

- The dataset is a **numerator**: ages of exploited code. It supports the
  descriptive percentile score, not a hazard rate — "risk per protocol-year at
  age t" additionally needs total protocol-years at risk per age bucket
  (planned: per-protocol code-age records in these same files).
- Victims with diamond/module-registry/beacon architectures emit no standard
  upgrade event; their ages may be overstated
  (`nonStandardUpgradeArchitecture: true`).
- Losses parsed from community sources are labeled as such; implausible
  figures were excluded.
- Old code is not safe: ~14% of measured code-bug exploits hit code older than
  two years (dormant compiler bugs, long-lived misconfigurations).

## Updating

1. Add or edit `protocols/<slug>.json` rows (measure with the verification
   method above; every `OK` row needs onchain anchors).
2. `node scripts/build-curve.mjs` and review the diff of the knots.
3. Cut `curve/v<YYYY-MM>.json`, record the change in `CHANGELOG.md`.
4. Consumers (the L2BEAT frontend) adopt the new curve as a deliberate,
   versioned release — scores never drift silently.

## License

Data: CC BY 4.0. Scripts: MIT.
