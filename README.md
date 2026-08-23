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
SOURCES.md              candidate lists and verification tooling behind the rows
scripts/build-curve.mjs deterministic curve rebuild (--check verifies a release)
scripts/verify.mjs      re-derive a protocol's measurements (RPC; Etherscan optional)
```

## Curve

`build-curve.mjs`: measured `code-bug` rows, one observation per
`(chain, victimContract, lastChange)` — re-exploiting the same code is not
independent, but a contract exploited again after its code changed is a fresh
observation (curated wins, then earliest incident), knots = sorted
`codeAgeSeconds`. Score = interpolated percentile with Weibull plotting
positions `p_i = (i+1)/(n+1)`.

## Updating

See `CONTRIBUTING.md` for the full inclusion rule, classification precedents,
and measurement procedure.
