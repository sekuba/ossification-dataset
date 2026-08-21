/**
 * Deterministically rebuilds the score curve from the protocol files.
 *
 * Inclusion rule (must match the published methodology):
 *   - category === 'code-bug'
 *   - measurement.status === 'OK'
 *   - one observation per (chain, victimContract): repeated exploits of the
 *     same contract are not independent. Curated rows win over registry rows,
 *     then the earliest incident wins; later collisions are dropped.
 *
 * Output: sorted exploited-code ages in seconds (the curve knots).
 *   node scripts/build-curve.mjs            # prints summary + writes curve/next.json
 *   node scripts/build-curve.mjs --check curve/v2026-08.json   # verify a release
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const dir = path.join(root, 'protocols')

const rows = []
for (const file of readdirSync(dir).sort()) {
  const doc = JSON.parse(readFileSync(path.join(dir, file), 'utf-8'))
  for (const incident of doc.incidents) rows.push(incident)
}

const isCurated = (r) => r.sources.some((s) => s.type === 'curated-review')
rows.sort((a, b) => Number(isCurated(b)) - Number(isCurated(a)) || a.date.localeCompare(b.date))

const seen = new Set()
const knots = []
for (const r of rows) {
  if (r.category !== 'code-bug' || r.measurement?.status !== 'OK') continue
  const key = `${r.chain}:${(r.victimContract ?? '').toLowerCase()}`
  if (r.victimContract) {
    if (seen.has(key)) continue
    seen.add(key)
  }
  knots.push(r.measurement.codeAgeSeconds)
}
knots.sort((a, b) => a - b)

const curve = {
  n: knots.length,
  rule: 'sorted exploited-code ages (seconds) of measured code-bug incidents, deduped by (chain, victimContract) with curated rows winning',
  score:
    'ossification(ageSeconds) = interpolated percentile within ageKnots using Weibull plotting positions p_i = (i+1)/(n+1)',
  ageKnots: knots,
}

const checkArg = process.argv.indexOf('--check')
if (checkArg !== -1) {
  const released = JSON.parse(readFileSync(path.join(root, process.argv[checkArg + 1]), 'utf-8'))
  const same = JSON.stringify(released.ageKnots) === JSON.stringify(curve.ageKnots)
  console.log(same ? `OK: rebuild matches (n=${curve.n})` : 'MISMATCH: rebuild differs from release')
  process.exit(same ? 0 : 1)
}
writeFileSync(path.join(root, 'curve', 'next.json'), `${JSON.stringify(curve, null, 2)}\n`)
console.log(`n=${curve.n}, median ${(knots[Math.floor(knots.length / 2)] / 86400 / 30.44).toFixed(1)}mo -> curve/next.json`)
