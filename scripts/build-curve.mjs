/**
 * Deterministically rebuilds the score curve from the protocol files.
 *
 * Inclusion rule (must match README and the published methodology):
 *   - category === 'code-bug' and measurement.status === 'OK'
 *   - one observation per (chain, victimContract, lastChangeTimestamp): a
 *     re-exploit of byte-identical code is not an independent observation of
 *     code failing at that age (it mostly measures response time), so it is
 *     collapsed - curated rows win, then the earliest incident. A contract
 *     exploited again AFTER its code changed has a new lastChange and counts
 *     again. A row with independentFlaw: true documents a genuinely distinct,
 *     independently found flaw in the same code state and also counts.
 *
 * Output: sorted exploited-code ages in seconds (the curve knots).
 *   node scripts/build-curve.mjs            # summary + writes curve/next.json
 *   node scripts/build-curve.mjs --check-latest   # verify the current release
 *   node scripts/build-curve.mjs --check curve/v2026-08.json   # verify a specific one
 *   node scripts/build-curve.mjs --stats    # dataset stats for SOURCES.md/CHANGELOG
 *   node scripts/build-curve.mjs --floor 100000   # preview the curve at a
 *     higher loss floor (prints only; never writes). Use before changing the
 *     inclusion floor so the score shift is a known, deliberate quantity.
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const dir = path.join(root, 'protocols')

const rows = []
const files = readdirSync(dir).sort()
for (const file of files) {
  const doc = JSON.parse(readFileSync(path.join(dir, file), 'utf-8'))
  for (const incident of doc.incidents) rows.push({ file, ...incident })
}

// Curated rows win the dedup, then the earliest incident.
const isCurated = (r) => r.sources.some((s) => s.type === 'curated-review')
rows.sort((a, b) => Number(isCurated(b)) - Number(isCurated(a)) || a.date.localeCompare(b.date))

const seen = new Set()
const knots = []
const collapsed = []
for (const r of rows) {
  if (r.category !== 'code-bug' || r.measurement?.status !== 'OK') continue
  const key = `${r.chain}:${r.victimContract?.toLowerCase()}:${r.measurement.lastChangeTimestamp}`
  if (seen.has(key) && r.independentFlaw !== true) {
    collapsed.push(`${r.file} "${r.name}" (${key})`)
    continue
  }
  seen.add(key)
  knots.push(r.measurement.codeAgeSeconds)
}
knots.sort((a, b) => a - b)

const curve = {
  n: knots.length,
  rule:
    'sorted exploited-code ages (seconds) of measured code-bug incidents, one observation per (chain, victimContract, lastChange) - curated wins, then earliest; independentFlaw rows also count',
  score:
    'ossification(ageSeconds) = interpolated percentile within ageKnots using Weibull plotting positions p_i = (i+1)/(n+1)',
  ageKnots: knots,
}

if (process.argv.includes('--stats')) {
  const st = {}
  let lossUsd = 0
  let measured = 0
  for (const r of rows) {
    for (const s of r.sources) st[s.type] = (st[s.type] ?? 0) + 1
    lossUsd += r.lossUsd ?? 0
    if (r.measurement?.status === 'OK') measured++
  }
  console.log(`files: ${files.length}`)
  console.log(`incidents: ${rows.length} (${measured} measured)`)
  console.log(`curve knots: ${curve.n} (${collapsed.length} collapsed by dedup)`)
  console.log(`total lossUsd: $${(lossUsd / 1e9).toFixed(2)}bn`)
  for (const [type, count] of Object.entries(st).sort((a, b) => b[1] - a[1])) console.log(`sources ${type}: ${count}`)
  process.exit(0)
}

const floorArg = process.argv.indexOf('--floor')
if (floorArg !== -1) {
  const floor = Number(process.argv[floorArg + 1])
  if (!Number.isFinite(floor)) {
    console.error('usage: node scripts/build-curve.mjs --floor <usd>')
    process.exit(1)
  }
  // Rows with a null lossUsd have no comparable figure, so a floor cannot
  // include them: report them separately instead of silently dropping them.
  const seenAtFloor = new Set()
  const kept = []
  let unpriced = 0
  for (const r of rows) {
    if (r.category !== 'code-bug' || r.measurement?.status !== 'OK') continue
    const key = `${r.chain}:${r.victimContract?.toLowerCase()}:${r.measurement.lastChangeTimestamp}`
    if (seenAtFloor.has(key) && r.independentFlaw !== true) continue
    if (r.lossUsd === null) {
      unpriced++
      continue
    }
    if (r.lossUsd < floor) continue
    seenAtFloor.add(key)
    kept.push(r.measurement.codeAgeSeconds)
  }
  kept.sort((a, b) => a - b)
  const q = (arr, p) => arr[Math.floor(arr.length * p)] ?? 0
  const pct = (arr, f) => ((arr.filter(f).length / arr.length) * 100).toFixed(1)
  console.log(`floor $${floor.toLocaleString()}: n=${kept.length} (current n=${curve.n}), ${unpriced} unpriced code-bug rows excluded`)
  for (const p of [0.1, 0.25, 0.5, 0.75, 0.9]) {
    console.log(
      `  p${p * 100}: ${(q(kept, p) / 86400).toFixed(1)}d (current ${(q(curve.ageKnots, p) / 86400).toFixed(1)}d)`,
    )
  }
  console.log(`  under 1 day: ${pct(kept, (x) => x < 86400)}% (current ${pct(curve.ageKnots, (x) => x < 86400)}%)`)
  console.log(`  over 1 year: ${pct(kept, (x) => x > 31536000)}% (current ${pct(curve.ageKnots, (x) => x > 31536000)}%)`)
  process.exit(0)
}

// --check-latest resolves curve/latest.json, so a release bump needs no edits
// in package.json or CI; --check <file> pins an explicit release.
const checkArg = process.argv.indexOf('--check')
const checkLatest = process.argv.includes('--check-latest')
if (checkArg !== -1 || checkLatest) {
  const releasePath = checkLatest
    ? path.join(root, 'curve', JSON.parse(readFileSync(path.join(root, 'curve', 'latest.json'), 'utf-8')).file)
    : path.join(root, process.argv[checkArg + 1])
  const released = JSON.parse(readFileSync(releasePath, 'utf-8'))
  const same = JSON.stringify(released.ageKnots) === JSON.stringify(curve.ageKnots)
  const name = path.basename(releasePath)
  console.log(
    same
      ? `OK: rebuild matches ${name} (n=${curve.n})`
      : `MISMATCH: rebuild (n=${curve.n}) differs from ${name} (n=${released.ageKnots.length})`,
  )
  process.exit(same ? 0 : 1)
}

for (const c of collapsed) console.log(`dedup: collapsed ${c}`)
writeFileSync(path.join(root, 'curve', 'next.json'), `${JSON.stringify(curve, null, 2)}\n`)
console.log(
  `n=${curve.n} (${collapsed.length} collapsed), median ${(knots[Math.floor(knots.length / 2)] / 86400).toFixed(1)}d -> curve/next.json`,
)
