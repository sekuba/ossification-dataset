import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'

const KIND_INDEX = {
  deployment: 0,
  'implementation-change': 1,
  'module-change': 2,
  'configuration-change': 3,
}

const curve = JSON.parse(readFileSync('dist/latest/curve.json', 'utf8'))
const release = JSON.parse(readFileSync('dist/latest/incidents.json', 'utf8'))
const incidents = new Map(release.incidents.map((i) => [i.id, i]))

const observationsPerIncident = new Map()
for (const o of curve.observations) {
  observationsPerIncident.set(
    o.incidentId,
    (observationsPerIncident.get(o.incidentId) ?? 0) + 1,
  )
}

const rows = curve.observations.map((o) => {
  const incident = incidents.get(o.incidentId)
  if (!incident) throw new Error(`incident missing from release: ${o.incidentId}`)
  const usd = incident.loss.usd?.amount
  if (!(usd >= 1000)) throw new Error(`curve observation without loss.usd: ${o.incidentId}`)
  const kind = KIND_INDEX[o.ageResetKind]
  if (kind === undefined) throw new Error(`unknown ageResetKind: ${o.ageResetKind}`)
  const timestamp = o.exploit.timestamp
  if (!timestamp) throw new Error(`curve observation without exploit timestamp: ${o.incidentId}`)
  const txHash = incident.exploit.transactionHash
  const sourceFile = `incidents/${o.chainId}/${txHash}.json`
  if (!existsSync(sourceFile)) throw new Error(`source record missing: ${sourceFile}`)
  return [
    o.codeAgeSeconds,
    Math.round(usd * 100) / 100,
    kind,
    o.chainId,
    timestamp,
    incident.protocol.name,
    observationsPerIncident.get(o.incidentId),
    txHash,
  ]
})
if (rows.length !== curve.counts.curveObservations) {
  throw new Error(`row count ${rows.length} != counts.curveObservations ${curve.counts.curveObservations}`)
}

const meta = {
  repo: `https://github.com/${process.env.GITHUB_REPOSITORY ?? 'sekuba/ossification-dataset'}`,
  generatedAt: new Date().toISOString().slice(0, 10),
  commit: (process.env.GITHUB_SHA ?? '').slice(0, 7),
  counts: {
    selected: curve.counts.curveObservations,
    provisional: curve.counts.provisionalObservations,
    deduplicated: curve.counts.deduplicatedObservations,
    other: curve.counts.otherExcludedObservations,
  },
}

let html = readFileSync('site/template.html', 'utf8')
for (const [placeholder, value] of [
  ['/*__ROWS__*/[]', JSON.stringify(rows)],
  ['/*__META__*/{}', JSON.stringify(meta)],
]) {
  if (!html.includes(placeholder)) throw new Error(`template placeholder missing: ${placeholder}`)
  html = html.replace(placeholder, value)
}

mkdirSync('_site', { recursive: true })
writeFileSync('_site/index.html', html)
console.log(`_site/index.html: ${rows.length} observations, data ${meta.generatedAt}`)
