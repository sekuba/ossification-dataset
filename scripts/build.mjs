/**
 * Build the deterministic, audit-oriented distribution in dist/latest.
 *
 * Source files are never modified. Every target is retained either as a curve
 * observation, a deduplicated observation, or an explicitly excluded
 * observation. Only reviewed incidents explicitly marked curve-eligible can
 * contribute a knot.
 *
 *   node scripts/build.mjs          # write dist/latest
 *   node scripts/build.mjs --check  # fail if dist/latest is stale
 */
import { createHash } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
export const LOSS_FLOOR_USD = 1_000

export const COHORT_RULES = {
  unit: 'one target-level observation per (codeArtifact.codeHash, failureModeId)',
  datasetAdmission:
    `losses meet the ${LOSS_FLOOR_USD} USD floor through loss.usd or an evidenced loss.minimumUsd lower bound`,
  curveUsdComparability:
    'the curve is narrower than dataset admission: it requires a concrete loss.usd.amount, not only a lower bound',
  curveInclusion: [
    'incident verification.tier equals reviewed',
    'target verification.tier equals reviewed',
    'target verification.curveEligible equals true',
    `loss.usd.amount is at least ${LOSS_FLOOR_USD}`,
    'ageReset.kind describes deployment, executable-code change, or a causal configuration change',
  ],
  ageResetKinds: ['deployment', 'implementation-change', 'module-change', 'configuration-change'],
  deduplication:
    'two passes, each keeping the earliest exploit under the deterministic selection order: first group by (incidentId, failureModeId) so sibling instances of one template collapse to one observation, then by (codeArtifact.codeHash, failureModeId) so byte-identical artifacts collapse across incidents',
  deduplicationSelectionOrder:
    'for observations on the same chain with complete exploit anchors: blockNumber, transactionIndex, timestamp, incidentId, target id; otherwise: timestamp, chainId, incidentId, target id',
  incidentReference:
    'observation.incidentId resolves the incident-level summary and loss in incidents.json, which lists reviewed incidents only; loss is intentionally not copied onto each target observation, and an incident that contributes several observations owns one loss, so a loss-weighted curve must aggregate per incidentId rather than sum per observation',
  ordering: 'ascending codeAgeSeconds, then observationId',
  excludedTargetTiers: ['provisional'],
}

function walkJsonFiles(dir, relativeTo = dir) {
  if (!existsSync(dir)) return []
  const result = []
  for (const entry of readdirSync(dir).sort()) {
    const absolute = path.join(dir, entry)
    const relative = path.relative(relativeTo, absolute).split(path.sep).join('/')
    const stat = statSync(absolute)
    if (stat.isDirectory()) result.push(...walkJsonFiles(absolute, relativeTo))
    else if (stat.isFile() && entry.endsWith('.json')) result.push({ absolute, relative })
  }
  return result
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

export function serialize(value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}

// Source files store unresolved anchor fields as absent, and a deployment-kind
// ageReset as {kind, description?} with its anchor derived from `deployment`.
// Scripts work on the normalized form, where unresolved is null and every
// ageReset carries explicit anchors and mechanism.
export function normalizeIncident(incident) {
  const exploit = incident.incident?.exploit
  if (exploit) {
    exploit.blockNumber ??= null
    exploit.transactionIndex ??= null
  }
  if (incident.loss) {
    incident.loss.usd ??= null
    incident.loss.minimumUsd ??= null
  }
  for (const target of incident.targets ?? []) {
    target.codeArtifact ??= {}
    target.codeArtifact.address ??= null
    target.codeArtifact.codeHash ??= null
    const deployment = target.deployment ?? {}
    for (const key of ['blockNumber', 'transactionHash', 'transactionIndex', 'creatorAddress'])
      deployment[key] ??= null
    const reset = target.ageReset
    if (!reset) continue
    if (reset.kind === 'deployment') {
      for (const key of ['timestamp', 'blockNumber', 'transactionHash', 'transactionIndex'])
        reset[key] = deployment[key] ?? null
      reset.logIndex = null
      reset.mechanism = { type: 'deployment', address: target.executionAddress }
    } else {
      for (const key of ['blockNumber', 'transactionHash', 'transactionIndex', 'logIndex'])
        reset[key] ??= null
    }
    reset.description ??= null
  }
  return incident
}

// Inverse of normalizeIncident: the canonical on-disk form.
export function incidentToDisk(incident) {
  const clone = structuredClone(incident)
  const exploit = clone.incident.exploit
  if (exploit.blockNumber === null) delete exploit.blockNumber
  if (exploit.transactionIndex === null) delete exploit.transactionIndex
  if (clone.loss.usd === null) delete clone.loss.usd
  if (clone.loss.minimumUsd === null) delete clone.loss.minimumUsd
  for (const target of clone.targets) {
    if (target.codeArtifact) {
      if (target.codeArtifact.address === null) delete target.codeArtifact.address
      if (target.codeArtifact.codeHash === null) delete target.codeArtifact.codeHash
      if (Object.keys(target.codeArtifact).length === 0) delete target.codeArtifact
    }
    for (const key of ['blockNumber', 'transactionHash', 'transactionIndex', 'creatorAddress'])
      if (target.deployment[key] === null) delete target.deployment[key]
    const reset = target.ageReset
    if (reset.kind === 'deployment') {
      target.ageReset = {
        kind: 'deployment',
        ...(reset.description ? { description: reset.description } : {}),
      }
    } else {
      for (const key of ['blockNumber', 'transactionHash', 'transactionIndex', 'logIndex', 'description'])
        if (reset[key] === null) delete reset[key]
    }
  }
  return clone
}

export function readIncidentSources(root = ROOT) {
  const directory = path.join(root, 'incidents')
  const files = walkJsonFiles(directory)
  if (files.length === 0) throw new Error('incidents/: no JSON source files found')

  return files.map(({ absolute, relative }) => {
    const raw = readFileSync(absolute, 'utf8')
    let incident
    try {
      incident = JSON.parse(raw)
    } catch (error) {
      throw new Error(`incidents/${relative}: invalid JSON: ${error.message}`)
    }
    return {
      path: `incidents/${relative}`,
      raw,
      sha256: sha256(raw),
      incident: normalizeIncident(incident),
    }
  })
}

function numericUsd(loss) {
  const amount = loss?.usd?.amount
  return typeof amount === 'number' && Number.isFinite(amount) ? amount : null
}

function observationDetails(record, target) {
  const incident = record.incident
  return {
    observationId: `${incident.id}#${target.id}`,
    incidentId: incident.id,
    targetId: target.id,
    chainId: incident.incident.chainId,
    exploit: {
      blockNumber: incident.incident.exploit.blockNumber,
      transactionIndex: incident.incident.exploit.transactionIndex,
      timestamp: incident.incident.exploit.timestamp,
    },
    incidentVerificationTier: incident.verification.tier,
    targetVerificationTier: target.verification.tier,
    targetCurveEligible: target.verification.curveEligible,
    failureModeId: target.failureModeId,
    codeArtifactCodeHash: target.codeArtifact.codeHash,
    ageResetKind: target.ageReset.kind,
    codeAgeSeconds: target.codeAgeSeconds,
  }
}

function exclusionReasons(incident, target) {
  const reasons = []
  if (incident.verification?.tier !== 'reviewed')
    reasons.push(`incident-verification-tier:${incident.verification?.tier ?? 'missing'}`)
  if (target.verification?.tier !== 'reviewed')
    reasons.push(`target-verification-tier:${target.verification?.tier ?? 'missing'}`)
  if (target.verification?.curveEligible !== true)
    reasons.push('target-verification:not-curve-eligible')

  const usd = numericUsd(incident.loss)
  if (usd === null) reasons.push('loss:no-usd-valuation')
  else if (usd < LOSS_FLOOR_USD) reasons.push('loss:below-floor')

  if (!COHORT_RULES.ageResetKinds.includes(target.ageReset?.kind))
    reasons.push(`age-reset:${target.ageReset?.kind ?? 'missing'}`)
  return reasons
}

function increment(object, key) {
  object[key] = (object[key] ?? 0) + 1
}

function countBy(records, value) {
  const result = {}
  for (const record of records) increment(result, value(record) ?? 'missing')
  return Object.fromEntries(Object.entries(result).sort(([a], [b]) => compareText(a, b)))
}

function compareCandidates(a, b) {
  if (
    a.chainId === b.chainId &&
    a.exploit.blockNumber !== null && a.exploit.transactionIndex !== null &&
    b.exploit.blockNumber !== null && b.exploit.transactionIndex !== null
  ) {
    const onchainOrder =
      a.exploit.blockNumber - b.exploit.blockNumber ||
      a.exploit.transactionIndex - b.exploit.transactionIndex
    if (onchainOrder !== 0) return onchainOrder
  }
  return (
    a.exploit.timestamp - b.exploit.timestamp ||
    a.chainId - b.chainId ||
    compareText(a.incidentId, b.incidentId) ||
    compareText(a.observationId, b.observationId)
  )
}

function compareCurveObservations(a, b) {
  return a.codeAgeSeconds - b.codeAgeSeconds || compareText(a.observationId, b.observationId)
}

export function createCurve(records) {
  const eligible = []
  const provisionalObservations = []
  const otherExcludedObservations = []
  const exclusionReasonCounts = {}
  let sourceTargetCount = 0

  for (const record of records) {
    const incident = record.incident
    for (const target of incident.targets ?? []) {
      sourceTargetCount++
      const observation = observationDetails(record, target)
      const reasons = exclusionReasons(incident, target)
      if (reasons.length === 0) {
        eligible.push(observation)
        continue
      }
      for (const reason of reasons) increment(exclusionReasonCounts, reason)
      const excluded = { ...observation, exclusionReasons: reasons }
      if (incident.verification?.tier === 'provisional' || target.verification?.tier === 'provisional')
        provisionalObservations.push(excluded)
      else otherExcludedObservations.push(excluded)
    }
  }

  const deduplicatedObservations = []

  // Two collapse passes, narrowest first. Within one incident, sibling
  // instances of one template - a factory's clones, a beacon's proxies, a
  // router's pools - fail together through the same defect and carry one loss,
  // so they contribute one observation even though their bytecode differs by
  // deployment arguments. Across incidents, byte-identical artifacts failing
  // the same way collapse too.
  const collapse = (candidates, keyOf, keyFor) => {
    const groups = new Map()
    for (const observation of candidates) {
      const key = JSON.stringify(keyOf(observation))
      groups.set(key, [...(groups.get(key) ?? []), observation])
    }
    const kept = []
    for (const group of groups.values()) {
      group.sort(compareCandidates)
      const selected = group[0]
      kept.push(selected)
      for (const duplicate of group.slice(1)) {
        deduplicatedObservations.push({
          ...duplicate,
          duplicateOf: selected.observationId,
          deduplicationKey: keyFor(selected),
        })
      }
    }
    return kept
  }

  const observations = collapse(
    collapse(
      eligible,
      (observation) => [observation.incidentId, observation.failureModeId],
      (selected) => ({ incidentId: selected.incidentId, failureModeId: selected.failureModeId }),
    ),
    (observation) => [observation.codeArtifactCodeHash, observation.failureModeId],
    (selected) => ({
      codeArtifactCodeHash: selected.codeArtifactCodeHash,
      failureModeId: selected.failureModeId,
    }),
  )

  observations.sort(compareCurveObservations)
  deduplicatedObservations.sort((a, b) => compareText(a.observationId, b.observationId))
  provisionalObservations.sort((a, b) => compareText(a.observationId, b.observationId))
  otherExcludedObservations.sort((a, b) => compareText(a.observationId, b.observationId))

  return {
    $schema: '../../schema/release-curve.schema.json',
    formatVersion: 1,
    description: 'Empirical code ages at EVM exploits, reset by code or causal configuration changes.',
    cohortRules: COHORT_RULES,
    counts: {
      sourceIncidents: records.length,
      sourceTargets: sourceTargetCount,
      eligibleBeforeDeduplication: eligible.length,
      curveObservations: observations.length,
      deduplicatedObservations: deduplicatedObservations.length,
      provisionalObservations: provisionalObservations.length,
      otherExcludedObservations: otherExcludedObservations.length,
      incidentsByVerificationTier: countBy(records, (record) => record.incident.verification?.tier),
      targetsByVerificationTier: countBy(
        records.flatMap((record) => record.incident.targets ?? []),
        (target) => target.verification?.tier,
      ),
      exclusionReasons: Object.fromEntries(
        Object.entries(exclusionReasonCounts).sort(([a], [b]) => compareText(a, b)),
      ),
    },
    observations,
    ageKnots: observations.map((observation) => observation.codeAgeSeconds),
    deduplicatedObservations,
    provisionalObservations,
    otherExcludedObservations,
  }
}

function sourceManifest(records, root) {
  const schemaPath = path.join(root, 'schema', 'incident.schema.json')
  if (!existsSync(schemaPath)) throw new Error('schema/incident.schema.json does not exist')
  const schemaRaw = readFileSync(schemaPath, 'utf8')
  const files = records
    .map((record) => ({ path: record.path, sha256: record.sha256 }))
    .sort((a, b) => compareText(a.path, b.path))
  const datasetSha256 = sha256(files.map((file) => `${file.path}\u0000${file.sha256}\n`).join(''))
  const inputs = [
    ...files,
    { path: 'schema/incident.schema.json', sha256: sha256(schemaRaw) },
  ]
  const releaseSchemas = [
    'schema/release-incidents.schema.json',
    'schema/release-curve.schema.json',
    'schema/release-manifest.schema.json',
  ].map((relative) => {
    const absolute = path.join(root, relative)
    if (!existsSync(absolute)) throw new Error(`${relative} does not exist`)
    const entry = { path: relative, sha256: sha256(readFileSync(absolute, 'utf8')) }
    inputs.push(entry)
    return entry
  })
  const researchPath = path.join(root, 'research', 'candidates.json')
  const candidateSchemaPath = path.join(root, 'schema', 'candidate.schema.json')
  const research = {}
  if (existsSync(researchPath)) {
    const raw = readFileSync(researchPath, 'utf8')
    research.candidates = { path: 'research/candidates.json', sha256: sha256(raw) }
    inputs.push(research.candidates)
    const ledger = JSON.parse(raw)
    research.rawInputs = Object.values(ledger.generatedFrom ?? {})
      .filter((source) => typeof source?.file === 'string')
      .map((source) => {
        const absolute = path.resolve(root, source.file)
        const allowedRoot = `${path.resolve(root, 'research', 'raw')}${path.sep}`
        if (!absolute.startsWith(allowedRoot) || !existsSync(absolute))
          throw new Error(`research input must be an existing file under research/raw/: ${source.file}`)
        return { path: source.file, sha256: sha256(readFileSync(absolute)) }
      })
      .sort((a, b) => compareText(a.path, b.path))
    inputs.push(...research.rawInputs)
  }
  if (existsSync(candidateSchemaPath)) {
    const raw = readFileSync(candidateSchemaPath, 'utf8')
    research.candidateSchema = { path: 'schema/candidate.schema.json', sha256: sha256(raw) }
    inputs.push(research.candidateSchema)
  }
  inputs.sort((a, b) => compareText(a.path, b.path))
  return {
    incidentFiles: files,
    incidentFilesSha256: datasetSha256,
    allInputsSha256: sha256(inputs.map((file) => `${file.path}\u0000${file.sha256}\n`).join('')),
    schema: {
      path: 'schema/incident.schema.json',
      sha256: sha256(schemaRaw),
    },
    releaseSchemas,
    ...(Object.keys(research).length > 0 ? { research } : {}),
  }
}

export function buildArtifacts(root = ROOT) {
  const records = readIncidentSources(root)
  const ids = records.map((record) => record.incident.id)
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index)
  if (duplicateIds.length > 0)
    throw new Error(`duplicate incident IDs: ${[...new Set(duplicateIds)].sort().join(', ')}`)
  records.sort((a, b) => compareText(a.incident.id, b.incident.id))

  const incidents = {
    $schema: '../../schema/release-incidents.schema.json',
    formatVersion: 1,
    // Reviewed incidents only, and only the fields a curve observation cannot
    // supply. Provisional records await review; they stay in incidents/ and
    // are hashed in the manifest, but publishing their figures beside reviewed
    // ones invites summing the two together.
    incidents: records
      .filter(({ incident }) => incident.verification?.tier === 'reviewed')
      .map(({ incident }) => ({
      id: incident.id,
      protocol: incident.protocol,
      name: incident.name,
      chainId: incident.incident.chainId,
      exploit: incident.incident.exploit,
      summary: incident.summary,
      loss: incident.loss,
    })),
  }
  const curve = createCurve(records)
  const evidenceSources = records.flatMap((record) => record.incident.sources ?? [])
  const candidatePath = path.join(root, 'research', 'candidates.json')
  const candidateLedger = existsSync(candidatePath) ? JSON.parse(readFileSync(candidatePath, 'utf8')) : null
  const incidentsSerialized = serialize(incidents)
  const curveSerialized = serialize(curve)
  const sources = sourceManifest(records, root)
  const manifest = {
    $schema: '../../schema/release-manifest.schema.json',
    formatVersion: 1,
    description: 'Deterministic manifest for the latest ossification dataset distribution.',
    cohortRules: COHORT_RULES,
    counts: {
      incidentFiles: records.length,
      incidents: records.length,
      targets: curve.counts.sourceTargets,
      evidenceSources: evidenceSources.length,
      evidenceSourcesByType: countBy(evidenceSources, (source) => source.type),
      curveObservations: curve.counts.curveObservations,
      provisionalObservations: curve.counts.provisionalObservations,
      otherExcludedObservations: curve.counts.otherExcludedObservations,
      deduplicatedObservations: curve.counts.deduplicatedObservations,
      ...(candidateLedger
        ? {
            researchCandidates: candidateLedger.candidates?.length ?? 0,
            researchCandidatesBySource: Object.fromEntries(
              Object.entries(candidateLedger.counts?.bySource ?? {}).sort(([a], [b]) => compareText(a, b)),
            ),
            researchCandidatesByDisposition: Object.fromEntries(
              Object.entries(candidateLedger.counts?.byDisposition ?? {}).sort(([a], [b]) => compareText(a, b)),
            ),
            pendingOrUnresolvedResearchCandidates:
              (candidateLedger.counts?.byDisposition?.pending ?? 0) +
              (candidateLedger.counts?.byDisposition?.unresolved ?? 0),
          }
        : {}),
    },
    sources,
    artifacts: {
      'incidents.json': {
        bytes: Buffer.byteLength(incidentsSerialized),
        sha256: sha256(incidentsSerialized),
      },
      'curve.json': {
        bytes: Buffer.byteLength(curveSerialized),
        sha256: sha256(curveSerialized),
      },
    },
  }
  return {
    records,
    values: { incidents, curve, manifest },
    serialized: {
      'incidents.json': incidentsSerialized,
      'curve.json': curveSerialized,
      'manifest.json': serialize(manifest),
    },
  }
}

function main() {
  let build
  try {
    build = buildArtifacts(ROOT)
  } catch (error) {
    console.error(`ERROR: ${error.message}`)
    process.exitCode = 1
    return
  }

  const outputDirectory = path.join(ROOT, 'dist', 'latest')
  if (process.argv.includes('--check')) {
    const stale = []
    for (const [name, expected] of Object.entries(build.serialized)) {
      const output = path.join(outputDirectory, name)
      if (!existsSync(output) || readFileSync(output, 'utf8') !== expected) stale.push(`dist/latest/${name}`)
    }
    if (stale.length > 0) {
      console.error(`STALE: ${stale.join(', ')}; run node scripts/build.mjs`)
      process.exitCode = 1
      return
    }
    console.log(
      `OK: dist/latest is deterministic and current (${build.values.curve.counts.curveObservations} curve, ` +
        `${build.values.curve.counts.provisionalObservations} provisional)`,
    )
    return
  }

  mkdirSync(outputDirectory, { recursive: true })
  for (const [name, contents] of Object.entries(build.serialized))
    writeFileSync(path.join(outputDirectory, name), contents)
  console.log(
    `Built dist/latest: ${build.values.incidents.incidents.length} incidents, ` +
      `${build.values.curve.counts.curveObservations} curve observations, ` +
      `${build.values.curve.counts.provisionalObservations} provisional observations, ` +
      `${build.values.curve.counts.deduplicatedObservations} deduplicated observations.`,
  )
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main()
