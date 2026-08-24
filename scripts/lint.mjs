/**
 * Dependency-free validator for the dataset. Enforces the schema's shape plus
 * the cross-field invariants a JSON Schema cannot express. Run before every
 * commit; `npm test` runs it together with the curve release check.
 *
 * Exit code 0 = clean, 1 = errors. Warnings do not fail the build.
 */
import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const dir = path.join(root, 'protocols')

const CATEGORIES = [
  'code-bug',
  'oracle-manipulation',
  'economic-design',
  'governance-design',
  'key-compromise',
  'insider-rug',
  'offchain-infra',
]
const SOURCE_TYPES = ['onchain-tx', 'post-mortem', 'defihacklabs', 'curated-review']
const STATUSES = ['OK', 'SCOPE_ONLY']
const BASES = ['deployment', 'upgrade-events', 'documented']
const INCIDENT_KEYS = new Set([
  'name', 'date', 'chain', 'category', 'lossUsd', 'lossOther',
  'victimContract', 'exploitTx', 'attacker', 'notes',
  'documentedLastChange', 'nonStandardUpgradeArchitecture', 'independentFlaw',
  'sources', 'measurement',
])
const MEASUREMENT_KEYS = new Set([
  'status', 'incidentTimestamp', 'deployTimestamp', 'upgradeEventCount',
  'lastChangeTimestamp', 'codeAgeSeconds', 'basis',
])
const TOP_KEYS = new Set(['$schema', 'slug', 'name', 'incidents'])
const SOURCE_KEYS = new Set(['type', 'chain', 'ref'])

const ADDR = /^0x[0-9a-f]{40}$/
const TX = /^0x[0-9a-f]{64}$/
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/

const errors = []
const warnings = []
const err = (file, msg) => errors.push(`${file}: ${msg}`)
const warn = (file, msg) => warnings.push(`${file}: ${msg}`)

const byTx = new Map() // chain:tx -> file
const byCurveKey = new Map() // chain:victim:lastChange -> [{file, incident}]

for (const file of readdirSync(dir).sort()) {
  let doc
  try {
    doc = JSON.parse(readFileSync(path.join(dir, file), 'utf-8'))
  } catch (e) {
    err(file, `unparseable JSON: ${e.message}`)
    continue
  }
  for (const k of Object.keys(doc)) if (!TOP_KEYS.has(k)) err(file, `unknown top-level key "${k}"`)
  if (doc.slug !== file.replace(/\.json$/, '')) err(file, `slug "${doc.slug}" != filename`)
  if (!/^[a-z0-9-]+$/.test(doc.slug ?? '')) err(file, 'slug must be kebab-case')
  if (typeof doc.name !== 'string' || !doc.name) err(file, 'missing name')
  if (/(_exp|_exploit|\.sol$)/i.test(doc.name ?? '')) err(file, `name "${doc.name}" looks like a PoC filename, not a protocol name`)
  if (!Array.isArray(doc.incidents) || doc.incidents.length === 0) {
    err(file, 'incidents must be a non-empty array')
    continue
  }

  for (const inc of doc.incidents) {
    const label = `${file} "${inc.name ?? '?'}"`
    for (const k of Object.keys(inc)) if (!INCIDENT_KEYS.has(k)) err(label, `unknown incident key "${k}"`)
    for (const k of ['name', 'date', 'chain', 'category', 'notes']) {
      if (typeof inc[k] !== 'string') err(label, `missing/invalid ${k}`)
    }
    if (!DATE.test(inc.date ?? '')) err(label, `date "${inc.date}" not YYYY-MM-DDTHH:MM:SSZ`)
    if (!CATEGORIES.includes(inc.category)) err(label, `invalid category "${inc.category}"`)
    if (/(_exp|_exploit|\.sol$)/i.test(inc.name ?? '')) err(label, 'incident name looks like a PoC filename')

    // loss
    if (!('lossUsd' in inc)) err(label, 'missing lossUsd (use null when no high-confidence figure exists)')
    else if (inc.lossUsd === null) {
      if (typeof inc.lossOther !== 'string' || !inc.lossOther) err(label, 'lossUsd null requires lossOther')
    } else if (typeof inc.lossUsd !== 'number' || inc.lossUsd < 1000) {
      err(label, `lossUsd ${inc.lossUsd} below the 1000 inclusion floor`)
    }

    // anchors
    if (!('victimContract' in inc) || !('exploitTx' in inc)) err(label, 'victimContract and exploitTx are required (nullable)')
    if (inc.victimContract !== null && inc.victimContract !== undefined && !ADDR.test(inc.victimContract))
      err(label, `victimContract "${inc.victimContract}" not a lowercase 20-byte hex address`)
    if (inc.exploitTx !== null && inc.exploitTx !== undefined && !TX.test(inc.exploitTx))
      err(label, `exploitTx "${inc.exploitTx}" not a lowercase 32-byte hex hash`)
    if (inc.attacker !== undefined && !ADDR.test(inc.attacker))
      err(label, `attacker "${inc.attacker}" not a lowercase 20-byte hex address`)
    if (inc.victimContract && inc.exploitTx && inc.exploitTx.startsWith(inc.victimContract))
      err(label, 'victimContract is a truncation of exploitTx (data-entry artifact)')

    // sources
    if (!Array.isArray(inc.sources) || inc.sources.length === 0) err(label, 'sources must be non-empty')
    else {
      for (const s of inc.sources) {
        for (const k of Object.keys(s)) if (!SOURCE_KEYS.has(k)) err(label, `unknown source key "${k}"`)
        if (!SOURCE_TYPES.includes(s.type)) err(label, `invalid source type "${s.type}"`)
        if (typeof s.ref !== 'string' || !s.ref) err(label, 'source missing ref')
      }
      if (inc.exploitTx && !inc.sources.some((s) => s.type === 'onchain-tx' && s.ref.toLowerCase() === inc.exploitTx))
        err(label, 'exploitTx has no matching onchain-tx source entry')
    }

    // measurement
    const m = inc.measurement
    if (typeof m !== 'object' || m === null) {
      err(label, 'missing measurement')
      continue
    }
    for (const k of Object.keys(m)) if (!MEASUREMENT_KEYS.has(k)) err(label, `unknown measurement key "${k}"`)
    if (!STATUSES.includes(m.status)) err(label, `invalid measurement.status "${m.status}" (rejected candidates belong in exclusions.json)`)

    if (m.status === 'OK') {
      for (const k of ['incidentTimestamp', 'deployTimestamp', 'upgradeEventCount', 'lastChangeTimestamp', 'codeAgeSeconds']) {
        if (!Number.isInteger(m[k])) err(label, `measurement.${k} must be an integer when status is OK`)
      }
      if (!BASES.includes(m.basis)) err(label, `invalid basis "${m.basis}"`)
      if (Number.isInteger(m.incidentTimestamp) && Number.isInteger(m.lastChangeTimestamp)) {
        if (m.codeAgeSeconds !== m.incidentTimestamp - m.lastChangeTimestamp)
          err(label, `codeAgeSeconds ${m.codeAgeSeconds} != incident - lastChange (${m.incidentTimestamp - m.lastChangeTimestamp})`)
        if (m.codeAgeSeconds < 0) err(label, 'negative code age')
        if (m.lastChangeTimestamp < m.deployTimestamp) err(label, 'lastChange before deployment')
        const parsed = Date.parse(inc.date) / 1000
        if (Math.abs(parsed - m.incidentTimestamp) > 1)
          err(label, `date ${inc.date} != incidentTimestamp ${m.incidentTimestamp}`)
        if (m.lastChangeTimestamp === m.incidentTimestamp && m.basis !== 'documented')
          warn(label, 'lastChange equals the incident timestamp - confirm the change was not caused by the attacker (attacker-initiated changes must not count)')
      }
      if (m.basis === 'deployment' && m.lastChangeTimestamp !== m.deployTimestamp)
        err(label, 'basis "deployment" but lastChange != deployment')
      if (m.basis === 'upgrade-events' && m.upgradeEventCount < 1)
        err(label, 'basis "upgrade-events" but upgradeEventCount is 0')
      if (m.basis === 'documented' && !inc.documentedLastChange)
        err(label, 'basis "documented" requires documentedLastChange')
      if (inc.category === 'code-bug') {
        if (!inc.exploitTx) err(label, 'measured code-bug row requires exploitTx (inclusion rule 3)')
        if (!inc.victimContract) err(label, 'measured code-bug row requires victimContract (inclusion rule 2)')
        const key = `${inc.chain}:${inc.victimContract}:${m.lastChangeTimestamp}`
        if (!byCurveKey.has(key)) byCurveKey.set(key, [])
        byCurveKey.get(key).push({ file, name: inc.name, independentFlaw: inc.independentFlaw === true })
      }
    }

    if (inc.exploitTx) {
      const txKey = `${inc.chain}:${inc.exploitTx}`
      if (byTx.has(txKey)) err(label, `exploitTx duplicated in ${byTx.get(txKey)}`)
      else byTx.set(txKey, file)
    }
  }
}

for (const [key, rows] of byCurveKey) {
  if (rows.length > 1) {
    const overrides = rows.filter((r) => r.independentFlaw).length
    const kept = 1 + overrides
    warnings.push(
      `curve key ${key} has ${rows.length} incidents (${rows.map((r) => r.file).join(', ')}); ` +
      `${kept === rows.length ? 'all count (independentFlaw set)' : `${rows.length - kept} collapsed by dedup - set independentFlaw only for a genuinely distinct, independently found flaw`}`,
    )
  }
}

// A rejected candidate must not also be recorded as an incident: exclusions.json
// exists so rejections are not silently re-proposed.
try {
  const exclusions = JSON.parse(readFileSync(path.join(root, 'exclusions.json'), 'utf-8'))
  const seenEx = new Set()
  for (const e of exclusions.entries ?? []) {
    // chain is required so the "also recorded as an incident" check below can
    // actually key on it; without it a re-added candidate would slip through.
    if (!e.name || !e.reason || !e.chain)
      errors.push(`exclusions.json: entry missing name, chain or reason (${JSON.stringify(e).slice(0, 80)})`)
    if (e.exploitTx && !TX.test(e.exploitTx)) errors.push(`exclusions.json "${e.name}": exploitTx not a lowercase 32-byte hex hash`)
    if (e.exploitTx && byTx.has(`${e.chain}:${e.exploitTx}`))
      errors.push(`exclusions.json "${e.name}": excluded candidate is also recorded in ${byTx.get(`${e.chain}:${e.exploitTx}`)}`)
    const key = `${e.chain}:${e.exploitTx}`
    if (e.exploitTx && seenEx.has(key)) errors.push(`exclusions.json: duplicate entry for ${key}`)
    seenEx.add(key)
  }
} catch (e) {
  errors.push(`exclusions.json: unreadable (${e.message})`)
}

// The release pointer consumers resolve must name a real, self-consistent release.
try {
  const pointer = JSON.parse(readFileSync(path.join(root, 'curve', 'latest.json'), 'utf-8'))
  const release = JSON.parse(readFileSync(path.join(root, 'curve', pointer.file), 'utf-8'))
  if (release.version !== pointer.version)
    errors.push(`curve/latest.json: version ${pointer.version} != ${pointer.file} version ${release.version}`)
  if (release.ageKnots.length !== pointer.n)
    errors.push(`curve/latest.json: n ${pointer.n} != ${release.ageKnots.length} knots in ${pointer.file}`)
  if (release.ageKnots.some((v, i) => i > 0 && v < release.ageKnots[i - 1]))
    errors.push(`${pointer.file}: ageKnots are not sorted ascending`)
} catch (e) {
  errors.push(`curve/latest.json: unresolvable release pointer (${e.message})`)
}

for (const w of warnings) console.log(`WARN  ${w}`)
for (const e of errors) console.log(`ERROR ${e}`)
console.log(`\n${errors.length} errors, ${warnings.length} warnings across ${readdirSync(dir).length} files`)
process.exit(errors.length ? 1 : 0)
