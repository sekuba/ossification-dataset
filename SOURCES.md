# Sources

Every row cites its own provenance in its `sources` array. Across the 775
incidents: 740 `onchain-tx` anchors, 686 `defihacklabs` references, 591
`curated-review` notes recording what was verified onchain, and 419
`post-mortem` links.

## Candidate lists

- **Automated web research** — 480 candidates (2020–2026) of date, project,
  reported loss and candidate mechanism, worked through era by era:
  **108 rows (22%)**. The rest are non-EVM chains, custodial or hot-wallet
  drains with no victim contract, frontend and key compromises, and
  nominal-only loss figures.
- **[SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs)**
  @ `b3719ce` — 894 proof-of-concept exploits across 84 months, diffed against
  the dataset by victim address and exploit tx. 562 had no overlap at the start
  of the sweep and 161 after it; the dedicated pass took 478 entries to
  **326 rows**.
- **[Coinspect learn-evm-attacks](https://github.com/coinspect/learn-evm-attacks)**
  — verification cross-check for 2020–2021 victims and transactions; no rows
  attributed to it directly.

## Incident research and loss figures

419 post-mortem citations across 78 domains. The largest contributors:
X/Twitter alert threads (222 — PeckShield, TenArmor, DefimonAlerts, ExVul,
BlockSec, Blockaid and others), Medium write-ups (24), Telegram alert channels
(18), [rekt.news](https://rekt.news) (9), [BlockSec](https://blocksec.com) (16
across two hosts), [SolidityScan](https://blog.solidityscan.com) (7),
[Verichains](https://blog.verichains.io) (7), [Halborn](https://halborn.com)
(7), CertiK (6), [SlowMist](https://hacked.slowmist.io) (9 across two hosts),
QuillAudits (4). [DefiLlama](https://defillama.com/hacks) was used throughout
for cross-checking reported losses.
