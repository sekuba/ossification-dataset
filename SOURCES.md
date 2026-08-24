# Sources

Every row cites its own provenance in its `sources` array. Current counts come
from `node scripts/build-curve.mjs --stats` (regenerate this section from it,
never hand-edit the numbers). As of v2026-08.2: 757 incidents across 721
protocol files — 742 `onchain-tx` anchors, 668 `defihacklabs` references,
633 `curated-review` notes recording what was verified onchain, and 419
`post-mortem` links.

## Candidate lists

- **Automated web research** — the raw candidate list is committed as
  [`list-to-check.md`](list-to-check.md): 480 candidates (2020–2026) of date,
  project, reported loss and candidate mechanism, worked through era by era:
  **108 rows (22%)**. The rest are non-EVM chains, custodial or hot-wallet
  drains with no victim contract, frontend and key compromises, and
  nominal-only loss figures.
- **[SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)**
  @ `b3719ce` — the machine-generated coverage ledger is committed as
  [`dfhl-coverage.json`](dfhl-coverage.json): 869 PoC files under `src/test/`,
  660 matched to rows by `defihacklabs` ref, 73 covered under other
  identifiers (matched by exploit tx or victim address), 136 with no dataset
  row (each entry carries a one-line hint from the PoC header; curated
  rejections with full reasons live in `exclusions.json`).
- **[Coinspect learn-evm-attacks](https://github.com/coinspect/learn-evm-attacks)**
  — verification cross-check for 2020–2021 victims and transactions; no rows
  attributed to it directly.

## Incident research and loss figures

419 post-mortem citations across 78 domains. The largest contributors:
X/Twitter alert threads (PeckShield, TenArmor, DefimonAlerts, ExVul,
BlockSec, Blockaid and others), Medium write-ups, Telegram alert channels,
[rekt.news](https://rekt.news), [BlockSec](https://blocksec.com),
[SolidityScan](https://blog.solidityscan.com),
[Verichains](https://blog.verichains.io), [Halborn](https://halborn.com),
CertiK, [SlowMist](https://hacked.slowmist.io), QuillAudits.
[DefiLlama](https://defillama.com/hacks) was used throughout for
cross-checking reported losses.
