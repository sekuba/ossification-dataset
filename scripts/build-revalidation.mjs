#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const outputPath = join(root, 'research', 'revalidation.json')
const checkOnly = process.argv.includes('--check')

const BLOCKERS = [
  'incident-anchor',
  'root-cause',
  'loss',
  'target-relationship',
  'artifact-code-hash',
  'deployment-anchor',
  'code-change',
  'failure-mode',
  'target-evidence',
  'mechanical-verification',
  'semantic-review',
]

const REVIEWED_FAILURE_ID = /^failure:[a-z0-9]+(?:[-:][a-z0-9]+)*$/
const CODE_CHANGE_KINDS = new Set(['deployment', 'implementation-change', 'module-change'])
const CODE_CHANGE_MECHANISMS = new Set([
  'deployment',
  'event',
  'storage-write',
  'metamorphic-redeployment',
])

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function jsonFiles(directory) {
  if (!existsSync(directory)) return []
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name)
      if (entry.isDirectory()) return jsonFiles(path)
      return entry.isFile() && entry.name.endsWith('.json') ? [path] : []
    })
    .sort()
}

function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}

function inputDigest(paths) {
  const hash = createHash('sha256')
  for (const path of paths) {
    hash.update(`${relative(root, path)}\0`)
    hash.update(readFileSync(path))
    hash.update('\0')
  }
  return `sha256:${hash.digest('hex')}`
}

function hasClaim(sourceById, sourceId, claim) {
  return sourceById.get(sourceId)?.supports?.includes(claim) === true
}

function hasIncidentAnchor(incident, sourceById) {
  const exploit = incident.incident.exploit
  return (
    exploit.blockNumber !== null &&
    exploit.transactionIndex !== null &&
    [...sourceById.values()].some(
      (source) =>
        source.type === 'onchain-transaction' &&
        source.chainId === incident.incident.chainId &&
        source.transactionHash === exploit.transactionHash &&
        source.supports.includes('incident-anchor'),
    )
  )
}

function hasRootCauseEvidence(incident, sourceById) {
  return (
    incident.classification.rootCause === 'code-bug' &&
    [...sourceById.values()].some((source) => source.supports.includes('root-cause'))
  )
}

function hasReviewedLoss(incident, sourceById) {
  const loss = incident.loss
  const usd = loss.usd
  if (!['gross-assets-lost', 'net-loss', 'permanently-locked'].includes(loss.kind)) return false
  if (!['high', 'medium'].includes(loss.confidence)) return false
  if (!usd || usd.amount < 1_000 || usd.method === 'legacy-unspecified') return false
  if (usd.sourceIds.length === 0 || !usd.sourceIds.every((id) => hasClaim(sourceById, id, 'loss')))
    return false

  return loss.assets.every(
    (asset) =>
      'asset' in asset &&
      asset.sourceIds.length > 0 &&
      asset.sourceIds.every((id) => hasClaim(sourceById, id, 'loss')) &&
      (asset.valuation === null ||
        asset.valuation.sourceIds.every((id) => hasClaim(sourceById, id, 'loss'))),
  )
}

function completeDeployment(target) {
  const anchor = target.deployment
  return (
    anchor.blockNumber !== null &&
    anchor.transactionHash !== null &&
    anchor.transactionIndex !== null &&
    anchor.creatorAddress !== null
  )
}

function completeCodeChange(target) {
  const change = target.lastCodeChange
  const mechanism = change.mechanism
  if (
    change.blockNumber === null ||
    change.transactionHash === null ||
    change.transactionIndex === null ||
    !CODE_CHANGE_KINDS.has(change.kind) ||
    !CODE_CHANGE_MECHANISMS.has(mechanism.type)
  ) {
    return false
  }
  if (mechanism.type === 'event') {
    return change.logIndex !== null && mechanism.codeAddressLocation !== null
  }
  return true
}

function hasTargetEvidence(incident, target, sourceById) {
  const identityIds = target.evidence.identitySourceIds
  const historyIds = target.evidence.codeHistorySourceIds
  if (
    identityIds.length === 0 ||
    historyIds.length === 0 ||
    !identityIds.every((id) => hasClaim(sourceById, id, 'target-identity')) ||
    !historyIds.every((id) => hasClaim(sourceById, id, 'code-history'))
  ) {
    return false
  }

  for (const transactionHash of [
    target.deployment.transactionHash,
    target.lastCodeChange.transactionHash,
  ]) {
    if (transactionHash === null) return false
    const source = [...sourceById.values()].find(
      (candidate) =>
        candidate.type === 'onchain-transaction' &&
        candidate.chainId === incident.incident.chainId &&
        candidate.transactionHash === transactionHash &&
        candidate.supports.includes('code-history'),
    )
    if (!source || !historyIds.includes(source.id)) return false
  }
  return true
}

function blockersFor(incident, target, sourceById) {
  const blockers = []
  if (!hasIncidentAnchor(incident, sourceById)) blockers.push('incident-anchor')
  if (!hasRootCauseEvidence(incident, sourceById)) blockers.push('root-cause')
  if (!hasReviewedLoss(incident, sourceById)) blockers.push('loss')
  if (target.relationship === 'unknown') blockers.push('target-relationship')
  if (target.codeArtifact.address === null || target.codeArtifact.codeHash === null)
    blockers.push('artifact-code-hash')
  if (!completeDeployment(target)) blockers.push('deployment-anchor')
  if (!completeCodeChange(target)) blockers.push('code-change')
  if (!REVIEWED_FAILURE_ID.test(target.failureModeId)) blockers.push('failure-mode')
  if (!hasTargetEvidence(incident, target, sourceById)) blockers.push('target-evidence')
  if (target.verification.tier === 'provisional') blockers.push('mechanical-verification')
  if (
    incident.verification.tier !== 'reviewed' ||
    target.verification.tier !== 'reviewed' ||
    target.verification.curveEligible !== true
  ) {
    blockers.push('semantic-review')
  }
  return blockers
}

const incidentPaths = jsonFiles(join(root, 'incidents'))
const incidents = incidentPaths.map(readJson).sort((a, b) => compareText(a.id, b.id))
const items = []

for (const incident of incidents) {
  const sourceById = new Map(incident.sources.map((source) => [source.id, source]))
  for (const target of [...incident.targets].sort((a, b) => compareText(a.id, b.id))) {
    items.push({
      incidentId: incident.id,
      targetId: target.id,
      blockers: blockersFor(incident, target, sourceById),
    })
  }
}

const byBlocker = Object.fromEntries(BLOCKERS.map((blocker) => [blocker, 0]))
for (const item of items) {
  for (const blocker of item.blockers) byBlocker[blocker] += 1
}

const output = {
  $schema: '../schema/revalidation.schema.json',
  schemaVersion: '1.0.0',
  input: {
    incidentsSha256: inputDigest(incidentPaths),
    incidents: incidents.length,
    targets: items.length,
  },
  counts: {
    ready: items.filter((item) => item.blockers.length === 0).length,
    blocked: items.filter((item) => item.blockers.length > 0).length,
    byBlocker,
  },
  items,
}

const serialized = `${JSON.stringify(output, null, 2)}\n`
if (checkOnly) {
  if (!existsSync(outputPath) || readFileSync(outputPath, 'utf8') !== serialized) {
    console.error('research/revalidation.json is stale; run npm run revalidation')
    process.exit(1)
  }
  console.log(`research/revalidation.json is current (${items.length} targets)`)
} else {
  mkdirSync(join(root, 'research'), { recursive: true })
  writeFileSync(outputPath, serialized)
  console.log(`Wrote ${relative(root, outputPath)} (${items.length} targets)`)
}
