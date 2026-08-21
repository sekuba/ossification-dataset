# Ossification Dataset

The exploit dataset behind L2BEAT's **ossification score**: a protocol's score
is the percentile of its critical perimeter's age within this dataset's
exploited-code ages — *"ossification N = the unchanged perimeter has outlived
the code age of N% of recorded code-bug exploits."*

**Only `code-bug` incidents feed the curve.** Everything is verifiable from
public onchain data; `scripts/verify.mjs` re-derives any measured row.

## Layout

```
protocols/<slug>.json   one file per protocol: its incidents
curve/v<version>.json   released curve knots; changes only at versioned releases
schema/                 JSON Schema for protocol files
scripts/build-curve.mjs deterministic curve rebuild (--check verifies a release)
scripts/verify.mjs      re-derive a protocol's measurements from RPC + Etherscan
```

## Incident rows

Each row: onchain anchors (`exploitTx` — its block timestamp is the incident
time — `victimContract`, `chain`), the measurement (deploy timestamp,
pre-incident `Upgraded` events, `codeAgeSeconds`, evidence `basis`), a
root-cause `category` with one evidence sentence, verified USD loss
(USD-pegged stables at 1:1; crypto-only figures excluded), and provenance.
Rows that failed verification stay with their exclusion status
(`ATTACKER_DEPLOYED`, `NO_CREATION_INFO`, …) as audit trail.

## Categories

- `code-bug` — curve input, and nothing else is.
- `oracle-manipulation`, `economic-design`, `governance-design`,
  `insider-rug` — measured boundary rows: each documents why it is *not* a
  code bug (e.g. read-only reentrancy against a price feed; an owner using
  openly granted powers).
- `key-compromise`, `offchain-infra` — non-exhaustive context sample with no
  measurable code; bounds the metric's scope. Statistics over them describe
  this sample, not the population.
- `not-classified` — excluded before classification; see `measurement.status`.

## Curve

`build-curve.mjs`: measured `code-bug` rows, one observation per
`(chain, victimContract)` (curated wins, then earliest incident), knots =
sorted `codeAgeSeconds`. Score = interpolated percentile with Weibull plotting
positions `p_i = (i+1)/(n+1)`.

## Limitations

This is a numerator (ages of exploited code), not a hazard rate — that would
also need protocol-years at risk per age bucket (planned: per-protocol
code-age records in these files). Diamond/registry/beacon victims emit no
standard upgrade event (`nonStandardUpgradeArchitecture`; age may be
overstated). Old code is not safe: ~14% of measured code-bug exploits hit
code older than two years.

## Updating

Add or edit rows (measured, with onchain anchors) → `node
scripts/build-curve.mjs` → review the knot diff → cut `curve/v<YYYY-MM>.json`
and record it in `CHANGELOG.md`. Consumers adopt new curves as deliberate
releases; scores never drift silently.

## License

Data: CC BY 4.0. Scripts: MIT.
