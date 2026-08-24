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
exclusions.json         rejected candidates, each with its reason (append-only)
curve/v<version>.json   released curve knots; changes only at versioned releases
schema/                 JSON Schema for protocol files
SOURCES.md              candidate lists and verification tooling behind the rows
list-to-check.md        the raw web-research candidate list referenced by SOURCES.md
scripts/lint.mjs        offline validation: schema shape + cross-field invariants
scripts/build-curve.mjs deterministic curve rebuild (--check verifies a release, --stats prints dataset stats)
scripts/verify.mjs      re-derive measurements from RPC (single file or --all)
```

`npm test` = lint + rebuild-matches-release.

## Curve

`build-curve.mjs` takes every measured `code-bug` row and emits **one
observation per `(chain, victimContract, lastChange)`**.
Knots = sorted `codeAgeSeconds`.

Score = interpolated percentile with Weibull plotting positions
`p_i = (i+1)/(n+1)`.

## Updating

See `CONTRIBUTING.md` for the full inclusion rule, classification precedents,
and measurement procedure. Rejected candidates go to `exclusions.json`.
