import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'

const KIND_INDEX = {
  deployment: 0,
  'implementation-change': 1,
  'module-change': 2,
  'configuration-change': 3,
}

const release = JSON.parse(readFileSync('dist/latest/incidents.json', 'utf8'))

const rows = release.incidents.map((incident) => {
  const usd = incident.loss.usd?.amount
  if (!(usd >= 1000)) throw new Error(`curve incident without loss.usd: ${incident.id}`)
  const kind = KIND_INDEX[incident.ageResetKind]
  if (kind === undefined) throw new Error(`unknown ageResetKind: ${incident.ageResetKind}`)
  const txHash = incident.exploit.transactionHash
  const sourceFile = `incidents/${incident.chainId}/${txHash}.json`
  if (!existsSync(sourceFile)) throw new Error(`source record missing: ${sourceFile}`)
  return [
    incident.codeAgeSeconds,
    Math.round(usd * 100) / 100,
    kind,
    incident.chainId,
    incident.exploit.timestamp,
    incident.protocol.name,
    txHash,
  ]
})

const excluded = release.excluded
const meta = {
  repo: `https://github.com/${process.env.GITHUB_REPOSITORY ?? 'sekuba/ossification-dataset'}`,
  generatedAt: new Date().toISOString().slice(0, 10),
  commit: (process.env.GITHUB_SHA ?? '').slice(0, 7),
  counts: {
    curve: rows.length,
    provisional: excluded.filter((incident) => incident.verificationTier === 'provisional').length,
    reviewedExcluded: excluded.filter((incident) => incident.verificationTier === 'reviewed').length,
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
console.log(`_site/index.html: ${rows.length} incidents, data ${meta.generatedAt}`)
