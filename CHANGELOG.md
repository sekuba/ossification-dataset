# Changelog

## curve v2026-08.1 (2026-08-23)

767 incidents across 736 protocols, 744 measured; 629 curve knots (up from
243). $7.11bn in recorded losses. Sources and candidate-list yields are in
`SOURCES.md`.

Coverage. The DeFiHackLabs backlog was worked to completion against
`b3719ce`: 562 proof-of-concepts had no overlap with the dataset, 161 remain
(72 already recorded under other identifiers, 89 documented rejections). The
automated web-research list contributed 108 rows from 480 candidates. Eight
`SCOPE_ONLY` rows became measured curve inputs, among them Beanstalk, Cream,
UwU Lend and GMX.

The curve tripled without changing shape: under-1-day 12.3% -> 12.5%,
over-1-year 22.2% -> 22.4%, older-than-two-years 14.4% -> 14.3%. The median
falls 58.3d -> 42.3d and the tail extends to 3,038d.

## curve v2026-08 (2026-08-21)

Initial release. 320 incidents across 313 protocols (2017–2026), 282 with
onchain-measured exploited-code age; 243 curve knots (measured code-bug
incidents, one observation per contract). Sources: 51 hand-curated incidents
and 269 rows extracted from SunWeb3Sec/DeFiHackLabs @ ad353ba25fbb, every row
re-verified onchain (exploit tx, victim creation, pre-incident upgrade logs;
attacker-deployed "victims" excluded).
