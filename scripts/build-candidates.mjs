#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const outputPath = join(root, 'research', 'candidates.json')
const checkOnly = process.argv.includes('--check')
const COHORT_ID = 'evm-production-2026-07'
const COHORT_CUTOFF = '2026-07-31T23:59:59Z'
const COHORT_DFHL_MONTH = '2026-07'
const SEED_ROW_COUNT = 757

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function sourceDigest(paths) {
  const hash = createHash('sha256')
  for (const path of [...paths].sort()) {
    hash.update(`${relative(root, path)}\0`)
    hash.update(readFileSync(path))
    hash.update('\0')
  }
  return hash.digest('hex')
}

function jsonFiles(directory) {
  if (!existsSync(directory)) return []

  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name)
      return entry.isDirectory()
        ? jsonFiles(path)
        : entry.isFile() && entry.name.endsWith('.json')
          ? [path]
          : []
    })
    .sort()
}

function slug(value) {
  return value
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function normalizedName(value) {
  return value.normalize('NFKD').toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function unique(values) {
  return [...new Set(values)]
}

function compareStrings(a, b) {
  return a < b ? -1 : a > b ? 1 : 0
}

function parseDefiHackLabsPath(ref) {
  const match = ref.match(/^(src\/test\/[^ @()]+)/)
  if (!match) throw new Error(`Cannot parse DeFiHackLabs reference: ${ref}`)
  return match[1]
}

const DFHL_FULL_COMMITS = {
  b3719ce: 'b3719ce7fb93ee6f743853ede9471e1a8bed1de0',
  ad353ba25fbb: 'ad353ba25fbb897c56d64c28ce92ee10ac68cad2',
  '48c978bb245f': '48c978bb245f8b624a28903267ce0ae887f15504',
}

function fullDefiHackLabsCommit(ref, fallback) {
  const abbreviated = ref?.match(/@([0-9a-f]{7,40})/)?.[1]
  if (!abbreviated) return fallback
  if (abbreviated.length === 40) return abbreviated
  const resolved = DFHL_FULL_COMMITS[abbreviated]
  if (!resolved) throw new Error(`Unknown abbreviated DeFiHackLabs commit ${abbreviated}`)
  return resolved
}

function parsePrimaryIncidents(paths) {
  const records = []

  for (const path of paths) {
    const value = readJson(path)
    const values = Array.isArray(value)
      ? value
      : Array.isArray(value.incidents)
        ? value.incidents
        : [value]

    for (const incident of values) {
      if (
        incident &&
        typeof incident === 'object' &&
        typeof incident.id === 'string' &&
        /^eip155:\d+:0x[0-9a-f]{64}$/.test(incident.id)
      ) {
        records.push({
          path: relative(root, path),
          incident,
        })
      }
    }
  }

  const ids = records.map((record) => record.incident.id)
  if (new Set(ids).size !== ids.length) {
    throw new Error('Duplicate primary incident id')
  }

  return records
}

function dfhlPathsFromSeedRow(incident) {
  return (incident.sources ?? [])
    .filter((source) => source.type === 'defihacklabs')
    .map((source) => parseDefiHackLabsPath(source.ref))
}

const rawDirectory = join(root, 'research', 'raw')
const dfhlPath = join(rawDirectory, 'defihacklabs-coverage.json')
const webPath = join(rawDirectory, 'web-candidates.md')
const adjudicationsPath = join(rawDirectory, 'adjudications.json')
const seedPath = join(rawDirectory, 'seed-incidents.json')
const primaryPaths = jsonFiles(join(root, 'incidents'))

const dfhl = readJson(dfhlPath)
const adjudicationDocument = readJson(adjudicationsPath)
const adjudications = adjudicationDocument.entries.map((entry) => ({
  ...entry,
  disposition: entry.disposition ?? adjudicationDocument.defaultDisposition,
}))
if (
  adjudicationDocument.defaultDisposition !== 'excluded' ||
  adjudications.some((entry) => !['included', 'excluded', 'pending'].includes(entry.disposition))
) {
  throw new Error('research/raw/adjudications.json has an unsupported disposition')
}
const seed = readJson(seedPath)
const primaryRecords = parsePrimaryIncidents(primaryPaths)

const adjudicationIdsByExploitTx = new Map()
for (const [index, entry] of adjudications.entries()) {
  const transactionHash = entry.exploitTx?.toLowerCase()
  if (!/^0x[0-9a-f]{64}$/.test(transactionHash ?? '')) continue
  const adjudicationId = `adjudication:${index + 1}`
  adjudicationIdsByExploitTx.set(transactionHash, [
    ...(adjudicationIdsByExploitTx.get(transactionHash) ?? []),
    adjudicationId,
  ])
}

const primaryByTx = new Map()
const primaryByDfhlPath = new Map()
// Incidents declare the discovery leads they answer. Together with exploit-tx
// matching this is the only incident-to-lead link, and it is exact by
// construction.
const primaryByDiscoveryId = new Map()
for (const { incident } of primaryRecords) {
  const tx = incident.incident.exploit.transactionHash
  primaryByTx.set(tx, [...(primaryByTx.get(tx) ?? []), incident.id])
  for (const candidateId of incident.discovery ?? []) {
    primaryByDiscoveryId.set(candidateId, [
      ...(primaryByDiscoveryId.get(candidateId) ?? []),
      incident.id,
    ])
  }
  for (const source of incident.sources ?? []) {
    if (
      source.type === 'source-code' &&
      source.repository === 'https://github.com/SunWeb3Sec/DeFiHackLabs'
    ) {
      primaryByDfhlPath.set(source.path, [
        ...(primaryByDfhlPath.get(source.path) ?? []),
        incident.id,
      ])
    }
  }
}

if (seed.rows.length !== SEED_ROW_COUNT) {
  throw new Error(`research/raw/seed-incidents.json must contain the complete ${SEED_ROW_COUNT}-row inventory`)
}

function declaredIncidentIds(candidateId) {
  return primaryByDiscoveryId.get(candidateId) ?? []
}

const seedIdCounts = new Map()
const seedRows = seed.rows.map(({ source, protocol, incident }, contextIndex) => {
  const baseId = `seed:${protocol.slug}:${incident.date.slice(0, 10)}:${slug(incident.name)}`
  const ordinal = (seedIdCounts.get(baseId) ?? 0) + 1
  seedIdCounts.set(baseId, ordinal)
  const id = ordinal === 1 ? baseId : `${baseId}:${ordinal}`
  return {
    id,
    contextIndex,
    originalSource: source,
    protocolSlug: protocol.slug,
    protocolName: protocol.name,
    name: incident.name,
    date: incident.date,
    category: incident.category,
    measurementStatus: incident.measurement.status,
    exploitTx: incident.exploitTx,
    victimAddresses: incident.victimContract ? [incident.victimContract.toLowerCase()] : [],
    dfhlPaths: dfhlPathsFromSeedRow(incident),
    adjudicationIds: adjudicationIdsByExploitTx.get(incident.exploitTx?.toLowerCase()) ?? [],
    incidentIds: unique([
      ...(incident.exploitTx ? primaryByTx.get(incident.exploitTx.toLowerCase()) ?? [] : []),
      ...(primaryByDiscoveryId.get(id) ?? []),
    ]).sort(),
    protocol,
    incident,
  }
})

const directDfhlRows = new Map()
for (const row of seedRows) {
  for (const path of row.dfhlPaths) {
    directDfhlRows.set(path, [...(directDfhlRows.get(path) ?? []), row])
  }
}

const otherIdentifierByPoc = new Map(
  dfhl.coveredOtherIdentifier.map((entry) => [entry.poc, entry]),
)
const noDatasetRowByPoc = new Map(dfhl.noDatasetRow.map((entry) => [entry.poc, entry]))
// A seed category settles scope only when it names a cause outside executed
// EVM code.
// An adjudication may name the discovery leads it settles, the mirror of an
// incident's `discovery`. Without it an adjudication only reaches a lead that
// happens to share a seed row.
const adjudicationIdsByCandidateId = new Map()
for (const [index, entry] of adjudications.entries()) {
  for (const candidateId of entry.candidateIds ?? []) {
    adjudicationIdsByCandidateId.set(candidateId, [
      ...(adjudicationIdsByCandidateId.get(candidateId) ?? []),
      `adjudication:${index + 1}`,
    ])
  }
}

const CATEGORIES_OUTSIDE_COHORT = new Set(['insider-rug', 'key-compromise', 'offchain-infra'])

// These name a mechanism, not a cause. Each can be a defect in executed code, a
// causal persistent state change, or neither, so the row awaits causal review.
// The cohort is eip155-only, so a row on one of these chains yields no
// measurable EVM code state whatever its category says.
const NON_EVM_CHAINS = new Set(['solana', 'starknet', 'sui'])

const UNDECIDED_CATEGORIES = new Set([
  'economic-design',
  'governance-design',
  'oracle-manipulation',
])

const dfhlAdjudications = [
  ...(dfhl.adjudications?.lossBelowUsd1000 ?? []).map((poc) => ({
    poc,
    status: 'out-of-scope',
    reason: 'The pinned PoC reports a loss below the USD 1,000 cohort threshold.',
    evidence: { kind: 'source-hint' },
  })),
  ...(dfhl.adjudications?.sourceClassifications ?? []).map(({ poc, reason }) => ({
    poc,
    status: 'out-of-scope',
    reason,
    evidence: { kind: 'source-hint' },
  })),
  ...(dfhl.adjudications?.seedMatches ?? []).map(({ poc, entryIndex }) => ({
    poc,
    status: 'out-of-scope',
    reason: seedDisposition(seedRows[entryIndex]).reason,
    evidence: { kind: 'seed', entryIndex },
  })),
]
const dfhlAdjudicationByPoc = new Map()
for (const adjudication of dfhlAdjudications) {
  if (dfhlAdjudicationByPoc.has(adjudication.poc)) {
    throw new Error(`Duplicate DFHL adjudication for ${adjudication.poc}`)
  }
  if (adjudication.status !== 'out-of-scope') {
    throw new Error(`Unsupported DFHL adjudication status for ${adjudication.poc}`)
  }
  dfhlAdjudicationByPoc.set(adjudication.poc, adjudication)
}
const adjudicationsByPoc = new Map()
for (const [index, entry] of adjudications.entries()) {
  const path = entry.defihacklabs?.match(/^(src\/test\/[^@]+)/)?.[1]
  if (!path) continue
  adjudicationsByPoc.set(path, [...(adjudicationsByPoc.get(path) ?? []), index])
}
const adjudicationById = new Map(
  adjudications.map((entry, index) => [`adjudication:${index + 1}`, entry]),
)

function incidentIdsForAdjudication(adjudicationId) {
  const entry = adjudicationById.get(adjudicationId)
  const transactionHash = entry?.exploitTx?.toLowerCase()
  return unique([
    ...(transactionHash ? primaryByTx.get(transactionHash) ?? [] : []),
    ...(primaryByDiscoveryId.get(adjudicationId) ?? []),
  ]).sort()
}

function rowsForOtherIdentifier(entry) {
  const tx = entry.matchedBy.match(/^tx (0x[0-9a-f]{64})$/)?.[1]
  const victim = entry.matchedBy.match(/^victim (0x[0-9a-f]{40}) /)?.[1]
  const expectedSlug = basename(entry.datasetFile, '.json')
  const rows = seedRows.filter((row) => {
    if (row.protocolSlug !== expectedSlug) return false
    if (tx) return row.exploitTx?.toLowerCase() === tx
    if (victim) return row.victimAddresses.includes(victim)
    return false
  })

  if (rows.length === 0) {
    throw new Error(`Cannot resolve DFHL coverage match for ${entry.poc}`)
  }
  return rows
}

function seedCoordinates(row) {
  return {
    file: relative(root, seedPath),
    entryIndex: row.contextIndex,
    originalFile: row.originalSource.file,
    incidentIndex: row.originalSource.incidentIndex,
    name: row.name,
  }
}

// A victim-address or transaction match that several PoCs share cannot prove
// which campaign a seed row describes. Those rows stay context: only a PoC
// path an incident cites, or a lead it declares, resolves such a candidate.
function ambiguousOtherIdentifier(otherMatch, rows) {
  const frequency = Number(/freq=([0-9]+)/.exec(otherMatch?.matchedBy ?? '')?.[1] ?? 1)
  return frequency > rows.length
}

function explicitAdjudication(ids) {
  const adjudicationIds = unique(ids).sort()
  if (adjudicationIds.length === 0) return null
  const includedIds = adjudicationIds.filter(
    (adjudicationId) => adjudicationById.get(adjudicationId)?.disposition === 'included',
  )
  if (includedIds.length > 0) {
    const incidentIds = unique(includedIds.flatMap(incidentIdsForAdjudication)).sort()
    if (incidentIds.length === 0)
      throw new Error(`Included adjudication has no admitted incident: ${includedIds.join(', ')}`)
    return {
      status: 'included',
      incidentIds,
      adjudicationIds,
      reason: 'An exact adjudication links this lead to an admitted incident.',
    }
  }
  const pending = adjudicationIds.some(
    (adjudicationId) => adjudicationById.get(adjudicationId)?.disposition === 'pending',
  )
  return {
    status: pending ? 'pending' : 'excluded',
    adjudicationIds,
    reason: pending
      ? 'An exact adjudication reopened this lead under the causal critical-state rule.'
      : 'An exact adjudication excludes this lead from the primary dataset.',
  }
}

function dfhlDisposition(rows, poc, ambiguous = false) {
  const directIds = unique([
    ...(primaryByDfhlPath.get(poc) ?? []),
    ...declaredIncidentIds(`dfhl:${poc}`),
  ]).sort()
  const incidentIds = ambiguous
    ? directIds
    : unique([...rows.flatMap((row) => row.incidentIds), ...directIds]).sort()
  if (incidentIds.length > 0) {
    return {
      status: 'included',
      incidentIds,
      reason: 'The source is linked to at least one incident admitted to the primary dataset.',
    }
  }

  const adjudicated = explicitAdjudication([
    ...(adjudicationsByPoc.get(poc) ?? []).map((index) => `adjudication:${index + 1}`),
    ...rows.flatMap((row) => row.adjudicationIds),
    ...(adjudicationIdsByCandidateId.get(`dfhl:${poc}`) ?? []),
  ])
  if (adjudicated) return adjudicated

  if (ambiguous) {
    return {
      status: 'pending',
      reason:
        'The pinned PoC matches its seed row only through an identifier several PoCs share, so the row cannot show which campaign this PoC reproduces. An incident must cite this PoC path or declare the lead.',
    }
  }

  if (rows.length > 0) {
    const allOutsidePrimaryScope = rows.every(
      (row) =>
        CATEGORIES_OUTSIDE_COHORT.has(row.category) || row.measurementStatus === 'SCOPE_ONLY',
    )
    return allOutsidePrimaryScope
      ? {
          status: 'out-of-scope',
          reason: 'The linked seed row is outside the primary code-bug dataset or was scope-only.',
        }
      : {
          status: 'pending',
          reason: 'A linked seed code-bug row exists, but no matching primary incident id was found.',
        }
  }

  return {
    status: 'unresolved',
    reason: 'The source snapshot has no seed row or explicit adjudication.',
  }
}

function seedDisposition(row) {
  const declared = declaredIncidentIds(row.id)
  if (row.incidentIds.length > 0) {
    return {
      status: 'included',
      incidentIds: row.incidentIds,
      reason:
        declared.length > 0
          ? 'An admitted incident declares this discovery lead.'
          : 'An admitted primary incident anchors this row\'s exploit transaction.',
    }
  }

  const adjudicated = explicitAdjudication([
    ...row.adjudicationIds,
    ...(adjudicationIdsByCandidateId.get(row.id) ?? []),
  ])
  if (adjudicated) return adjudicated

  if (CATEGORIES_OUTSIDE_COHORT.has(row.category)) {
    return {
      status: 'out-of-scope',
      reason: `The seed row category ${row.category} is outside the EVM code-bug cohort.`,
    }
  }

  if (NON_EVM_CHAINS.has(row.incident.chain)) {
    return {
      status: 'out-of-scope',
      reason: `The cohort measures EVM chains; this seed row records a ${row.incident.chain} incident.`,
    }
  }

  if (row.incident.notes.includes('chain-level precompile code')) {
    return {
      status: 'out-of-scope',
      reason:
        'The measured unit is executable EVM contract code; this defect is in a chain-level precompile.',
    }
  }

  if (UNDECIDED_CATEGORIES.has(row.category)) {
    return {
      status: 'pending',
      reason: `The seed inventory labelled this row ${row.category}, which names a mechanism rather than a cause. Review whether executed code violated an invariant or a persistent onchain configuration change created the vulnerable state.`,
    }
  }

  return {
    status: 'pending',
    reason:
      'The seed row is classified as an EVM code bug, but its primary incident claims are incomplete.',
  }
}

function seedOpenReason(row) {
  if (!row.exploitTx || row.victimAddresses.length === 0) return 'incident-anchors'
  if (row.incident.lossUsd === null || row.incident.lossUsd === undefined) {
    return 'loss-evidence'
  }
  return 'semantic-research'
}

const directPaths = new Set(directDfhlRows.keys())
const otherPaths = new Set(otherIdentifierByPoc.keys())
const noDatasetPaths = new Set(noDatasetRowByPoc.keys())
const allDfhlPaths = unique([...directPaths, ...otherPaths, ...noDatasetPaths]).sort()

if (allDfhlPaths.length !== dfhl.totalPocs) {
  throw new Error(
    `DFHL inventory mismatch: resolved ${allDfhlPaths.length}, expected ${dfhl.totalPocs}`,
  )
}

for (const adjudication of dfhlAdjudicationByPoc.values()) {
  if (!allDfhlPaths.includes(adjudication.poc)) {
    throw new Error(`DFHL adjudication references an unknown path: ${adjudication.poc}`)
  }

  if (adjudication.evidence.kind === 'source-hint') {
    const source = noDatasetRowByPoc.get(adjudication.poc)
    if (!source || source.hint === '(no header comment)') {
      throw new Error(`DFHL source-hint evidence is unavailable for ${adjudication.poc}`)
    }
  } else if (adjudication.evidence.kind === 'seed') {
    const row = seedRows[adjudication.evidence.entryIndex]
    if (!row || row.contextIndex !== adjudication.evidence.entryIndex) {
      throw new Error(`DFHL seed evidence is unavailable for ${adjudication.poc}`)
    }
  } else {
    throw new Error(`Unsupported DFHL adjudication evidence for ${adjudication.poc}`)
  }
}

const dfhlCandidates = allDfhlPaths.map((poc) => {
  const otherMatch = otherIdentifierByPoc.get(poc)
  const directRows = directDfhlRows.get(poc) ?? []
  const adjudication = dfhlAdjudicationByPoc.get(poc)
  const adjudicationRows =
    adjudication?.evidence.kind === 'seed'
      ? [seedRows[adjudication.evidence.entryIndex]]
      : []
  const rows = unique([
    ...(otherMatch ? rowsForOtherIdentifier(otherMatch) : directRows),
    ...adjudicationRows,
  ])
  const relatedAdjudicationIds = (adjudicationsByPoc.get(poc) ?? []).map(
    (index) => `adjudication:${index + 1}`,
  )
  const coverage = otherMatch
    ? {
        kind: 'other-identifier',
        matchedBy: otherMatch.matchedBy,
        ...(directRows.length > 0 ? { alsoHasDirectReference: true } : {}),
      }
    : directRows.length > 0
      ? { kind: 'direct-reference' }
      : {
          kind: 'no-dataset-row',
          hint: noDatasetRowByPoc.get(poc).hint,
        }

  return {
    id: `dfhl:${poc}`,
    source: {
      kind: 'defihacklabs',
      repository: 'https://github.com/SunWeb3Sec/DeFiHackLabs',
      commit: dfhl.commit,
      path: poc,
      url: `https://github.com/SunWeb3Sec/DeFiHackLabs/blob/${dfhl.commit}/${poc}`,
    },
    coverage,
    ...(relatedAdjudicationIds.length > 0 ? { relatedAdjudicationIds } : {}),
    ...(rows.length > 0
      ? { matchedRows: rows.map(seedCoordinates).sort((a, b) => compareStrings(a.file, b.file)) }
      : {}),
    disposition: adjudication
      ? { status: adjudication.status, reason: adjudication.reason }
      : dfhlDisposition(rows, poc, Boolean(otherMatch) && ambiguousOtherIdentifier(otherMatch, rows)),
  }
})

const actualDfhlCoverage = {
  directReference: dfhlCandidates.filter(
    (candidate) => candidate.coverage.kind === 'direct-reference',
  ).length,
  otherIdentifier: dfhlCandidates.filter(
    (candidate) => candidate.coverage.kind === 'other-identifier',
  ).length,
  noDatasetRow: dfhlCandidates.filter(
    (candidate) => candidate.coverage.kind === 'no-dataset-row',
  ).length,
}
if (
  actualDfhlCoverage.directReference !== dfhl.matchedByRef ||
  actualDfhlCoverage.otherIdentifier !== dfhl.coveredOtherIdentifier.length ||
  actualDfhlCoverage.noDatasetRow !== dfhl.noDatasetRow.length ||
  actualDfhlCoverage.otherIdentifier + actualDfhlCoverage.noDatasetRow !== dfhl.unmatched
) {
  throw new Error(
    `DFHL coverage buckets do not match ${relative(root, dfhlPath)}: ${JSON.stringify(actualDfhlCoverage)}`,
  )
}

const webLines = readFileSync(webPath, 'utf8').split(/\r?\n/)
const webRows = webLines.flatMap((line, index) => {
  const match = line.match(/^(\d{4}-\d{2}-\d{2}) \| ([^|]+) \| ([^|]+) \| (.+)$/)
  if (!match) return []
  return [
    {
      line: index + 1,
      date: match[1],
      project: match[2].trim(),
      reportedLoss: match[3].trim(),
      candidateMechanism: match[4].trim(),
    },
  ]
})

const webIdCounts = new Map()
const webCandidates = webRows.map((web) => {
  const baseId = `web:${web.date}:${slug(web.project)}`
  const ordinal = (webIdCounts.get(baseId) ?? 0) + 1
  webIdCounts.set(baseId, ordinal)
  const id = ordinal === 1 ? baseId : `${baseId}:${ordinal}`
  const candidateName = normalizedName(web.project)
  const exactSeedRows = seedRows.filter((row) => {
    if (row.date.slice(0, 10) !== web.date) return false
    return [row.protocolName, row.protocolSlug, row.name]
      .filter(Boolean)
      .some((name) => normalizedName(name) === candidateName)
  })
  const declared = declaredIncidentIds(id)
  const incidentIds = unique([
    ...exactSeedRows.flatMap((row) => row.incidentIds),
    ...declared,
  ]).sort()
  const adjudicationIds = unique([
    ...exactSeedRows.flatMap((row) => row.adjudicationIds),
    ...(adjudicationIdsByCandidateId.get(id) ?? []),
  ]).sort()
  const adjudicated = explicitAdjudication(adjudicationIds)
  const disposition =
    declared.length > 0
      ? {
          status: 'included',
          incidentIds,
          reason: 'An admitted incident declares this discovery lead.',
        }
      : incidentIds.length === 1
      ? {
          status: 'included',
          incidentIds,
          reason: 'Exact normalized project name and UTC date match one primary incident.',
        }
      : incidentIds.length === 0 && adjudicated
        ? adjudicated
        : {
          status: 'unresolved',
          reason:
            incidentIds.length > 1
              ? 'Exact name/date matching is ambiguous across multiple primary incidents.'
              : exactSeedRows.length > 0
                ? 'An exact seed-row name/date match exists, but it is not admitted to the primary dataset.'
                : 'No exact normalized project name and UTC date match was found; fuzzy matching was not used.',
        }

  return {
    id,
    source: {
      kind: 'web-list',
      file: relative(root, webPath),
      line: web.line,
    },
    candidate: {
      date: web.date,
      project: web.project,
      reportedLoss: web.reportedLoss,
      mechanism: web.candidateMechanism,
    },
    ...(exactSeedRows.length > 0
      ? { matchedRows: exactSeedRows.map(seedCoordinates) }
      : {}),
    ...(adjudicationIds.length > 0 ? { relatedAdjudicationIds: adjudicationIds } : {}),
    disposition,
  }
})

const adjudicationCandidates = adjudications.map((entry, index) => {
  const id = `adjudication:${index + 1}`
  const incidentIds = entry.disposition === 'included' ? incidentIdsForAdjudication(id) : []
  if (entry.disposition === 'included' && incidentIds.length === 0)
    throw new Error(`Included adjudication has no admitted incident: ${id}`)
  return {
    id,
    source: {
      kind: 'adjudication',
      file: relative(root, adjudicationsPath),
      entryIndex: index,
      ...(entry.defihacklabs
        ? {
            defihacklabs: {
              repository: 'https://github.com/SunWeb3Sec/DeFiHackLabs',
              commit: fullDefiHackLabsCommit(entry.defihacklabs, dfhl.commit),
              path: entry.defihacklabs.match(/^(src\/test\/[^@]+)/)?.[1],
              recordedRef: entry.defihacklabs,
            },
          }
        : {}),
    },
    candidate: {
      name: entry.name,
      chain: entry.chain,
      date: entry.date,
      candidateVictim: entry.candidateVictim,
      exploitTx: entry.exploitTx,
    },
    disposition: {
      status: entry.disposition,
      reason: entry.reason,
      ...(incidentIds.length > 0 ? { incidentIds } : {}),
    },
  }
})

const seedCandidates = seedRows.map((row) => ({
  id: row.id,
  source: {
    kind: 'seed',
    file: relative(root, seedPath),
    entryIndex: row.contextIndex,
    original: row.originalSource,
  },
  candidate: {
    protocol: row.protocol,
    name: row.incident.name,
    date: row.incident.date,
    chain: row.incident.chain,
    category: row.incident.category,
    measurementStatus: row.incident.measurement.status,
    ...(row.incident.lossUsd !== undefined ? { lossUsd: row.incident.lossUsd } : {}),
    ...(row.incident.lossOther !== undefined ? { lossOther: row.incident.lossOther } : {}),
    victimContract: row.incident.victimContract,
    exploitTx: row.incident.exploitTx,
    notes: row.incident.notes,
    sources: row.incident.sources ?? [],
  },
  disposition: seedDisposition(row),
}))

const candidates = [
  ...dfhlCandidates,
  ...webCandidates,
  ...adjudicationCandidates,
  ...seedCandidates,
].sort((a, b) => compareStrings(a.id, b.id))

const ids = candidates.map((candidate) => candidate.id)
if (new Set(ids).size !== ids.length) throw new Error('Duplicate candidate id')

const bySource = Object.fromEntries(
  [...new Set(candidates.map((candidate) => candidate.source.kind))]
    .sort()
    .map((kind) => [kind, candidates.filter((candidate) => candidate.source.kind === kind).length]),
)
const byDisposition = Object.fromEntries(
  [...new Set(candidates.map((candidate) => candidate.disposition.status))]
    .sort()
    .map((status) => [
      status,
      candidates.filter((candidate) => candidate.disposition.status === status).length,
    ]),
)

const cohortDfhl = dfhlCandidates.filter((candidate) => {
  const month = candidate.source.path.match(/^src\/test\/(\d{4}-\d{2})\//)?.[1]
  if (!month) throw new Error(`DFHL path has no calendar month: ${candidate.source.path}`)
  return month <= COHORT_DFHL_MONTH
})
const cohortSeed = seedRows.filter((row) => row.date <= COHORT_CUTOFF)
const cohortRecords = [
  ...cohortDfhl.map((candidate) => {
    const matchedSeed = candidate.matchedRows?.[0]
    const row =
      matchedSeed?.file === relative(root, seedPath)
        ? seedRows[matchedSeed.entryIndex]
        : undefined
    return {
      disposition: candidate.disposition.status,
      ...(candidate.disposition.status === 'pending'
        ? { openReason: row ? seedOpenReason(row) : 'semantic-research' }
        : candidate.disposition.status === 'unresolved'
          ? { openReason: 'semantic-research' }
          : {}),
    }
  }),
  ...cohortSeed.map((row) => {
    const disposition = seedDisposition(row).status
    return {
      disposition,
      ...(disposition === 'pending' ? { openReason: seedOpenReason(row) } : {}),
    }
  }),
]
const cohortByDisposition = Object.fromEntries(
  [...new Set(cohortRecords.map((record) => record.disposition))]
    .sort()
    .map((status) => [
      status,
      cohortRecords.filter((record) => record.disposition === status).length,
    ]),
)
const openReasons = cohortRecords.flatMap((record) =>
  record.openReason ? [record.openReason] : [],
)
const cohortOpenByReason = Object.fromEntries(
  ['incident-anchors', 'loss-evidence', 'semantic-research']
    .map((reason) => [reason, openReasons.filter((value) => value === reason).length]),
)

const result = {
  $schema: '../schema/candidate.schema.json',
  description:
    'Deterministic, source-addressed candidate dispositions. Overlapping source entries remain distinct.',
  cohort: {
    id: COHORT_ID,
    cutoff: COHORT_CUTOFF,
    cutoffBasis: 'latest-complete-source-calendar-month',
    sources: {
      defihacklabs: {
        generatedFrom: 'defihacklabs',
        dateField: 'path-month',
        through: COHORT_DFHL_MONTH,
      },
      seed: {
        generatedFrom: 'seed',
        dateField: 'incident.date',
      },
    },
    counts: {
      sourceRecords: cohortRecords.length,
      bySource: {
        defihacklabs: cohortDfhl.length,
        seed: cohortSeed.length,
      },
      byDisposition: cohortByDisposition,
      openByReason: cohortOpenByReason,
    },
  },
  generatedFrom: {
    defihacklabs: {
      file: relative(root, dfhlPath),
      commit: dfhl.commit,
      sha256: sha256(readFileSync(dfhlPath)),
    },
    webList: {
      file: relative(root, webPath),
      lineNumbers: '1-based',
      sha256: sha256(readFileSync(webPath)),
    },
    adjudications: {
      file: relative(root, adjudicationsPath),
      sha256: sha256(readFileSync(adjudicationsPath)),
    },
    seed: {
      file: relative(root, seedPath),
      rows: seed.rows.length,
      sha256: sha256(readFileSync(seedPath)),
    },
    primaryIncidents: {
      glob: 'incidents/**/*.json',
      files: primaryPaths.length,
      sha256: sourceDigest(primaryPaths),
    },
  },
  counts: {
    total: candidates.length,
    bySource,
    byDisposition,
    defihacklabsCoverage: {
      total: dfhlCandidates.length,
      ...actualDfhlCoverage,
    },
  },
  candidates,
}

const serialized = `${JSON.stringify(result, null, 2)}\n`

if (checkOnly) {
  if (!existsSync(outputPath)) {
    console.error(`Missing ${relative(root, outputPath)}; run node scripts/build-candidates.mjs`)
    process.exit(1)
  }
  const current = readFileSync(outputPath, 'utf8')
  if (current !== serialized) {
    console.error(`Stale ${relative(root, outputPath)}; run node scripts/build-candidates.mjs`)
    process.exit(1)
  }
  console.log(`${relative(root, outputPath)} is current (${candidates.length} entries)`)
} else {
  mkdirSync(join(root, 'research'), { recursive: true })
  writeFileSync(outputPath, serialized)
  console.log(`Wrote ${relative(root, outputPath)} (${candidates.length} entries)`)
}
