#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const outputPath = join(root, 'research', 'candidates.json')
const checkOnly = process.argv.includes('--check')

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
    .replace(/[\u0300-\u036f]/g, '')
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

function dfhlPathsFromLegacy(incident) {
  return (incident.sources ?? [])
    .filter((source) => source.type === 'defihacklabs')
    .map((source) => parseDefiHackLabsPath(source.ref))
}

const rawDirectory = join(root, 'research', 'raw')
const dfhlPath = join(rawDirectory, 'defihacklabs-coverage.json')
const webPath = join(rawDirectory, 'web-candidates.md')
const exclusionsPath = join(rawDirectory, 'exclusions.json')
const legacyV1Path = join(rawDirectory, 'legacy-v1.json')
const primaryPaths = jsonFiles(join(root, 'incidents'))

const dfhl = readJson(dfhlPath)
const exclusions = readJson(exclusionsPath).entries
const legacyV1 = readJson(legacyV1Path)
const primaryRecords = parsePrimaryIncidents(primaryPaths)

const primaryByTx = new Map()
for (const { incident } of primaryRecords) {
  const tx = incident.incident.exploit.transactionHash
  primaryByTx.set(tx, [...(primaryByTx.get(tx) ?? []), incident.id])
}

if (
  legacyV1.schemaVersion !== 1 ||
  legacyV1.source.files !== 721 ||
  legacyV1.source.incidents !== 757 ||
  legacyV1.rows.length !== 757
) {
  throw new Error('research/raw/legacy-v1.json must contain the complete 721-file / 757-row corpus')
}

const legacyRows = legacyV1.rows.map(({ source, protocol, incident }, contextIndex) => ({
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
  dfhlPaths: dfhlPathsFromLegacy(incident),
  incidentIds: incident.exploitTx
    ? primaryByTx.get(incident.exploitTx.toLowerCase()) ?? []
    : [],
  protocol,
  incident,
}))

const sourceRows = legacyRows
const directDfhlRows = new Map()
for (const row of sourceRows) {
  for (const path of row.dfhlPaths) {
    directDfhlRows.set(path, [...(directDfhlRows.get(path) ?? []), row])
  }
}

const otherIdentifierByPoc = new Map(
  dfhl.coveredOtherIdentifier.map((entry) => [entry.poc, entry]),
)
const noDatasetRowByPoc = new Map(dfhl.noDatasetRow.map((entry) => [entry.poc, entry]))
const exclusionsByPoc = new Map()
for (const [index, entry] of exclusions.entries()) {
  const path = entry.defihacklabs?.match(/^(src\/test\/[^@]+)/)?.[1]
  if (!path) continue
  exclusionsByPoc.set(path, [...(exclusionsByPoc.get(path) ?? []), index])
}

function rowsForOtherIdentifier(entry) {
  const tx = entry.matchedBy.match(/^tx (0x[0-9a-f]{64})$/)?.[1]
  const victim = entry.matchedBy.match(/^victim (0x[0-9a-f]{40}) /)?.[1]
  const expectedSlug = basename(entry.datasetFile, '.json')
  const rows = sourceRows.filter((row) => {
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

function legacyCoordinates(row) {
  return {
    file: relative(root, legacyV1Path),
    entryIndex: row.contextIndex,
    originalFile: row.originalSource.file,
    incidentIndex: row.originalSource.incidentIndex,
    name: row.name,
  }
}

function dfhlDisposition(rows, poc) {
  const incidentIds = unique(rows.flatMap((row) => row.incidentIds)).sort()
  if (incidentIds.length > 0) {
    return {
      status: 'included',
      incidentIds,
      reason: 'The source is linked to at least one incident admitted to the primary dataset.',
    }
  }

  if (rows.length > 0) {
    const allOutsidePrimaryScope = rows.every(
      (row) => row.category !== 'code-bug' || row.measurementStatus === 'SCOPE_ONLY',
    )
    return allOutsidePrimaryScope
      ? {
          status: 'out-of-scope',
          reason: 'The linked legacy row is outside the primary code-bug dataset or was scope-only.',
        }
      : {
          status: 'pending',
          reason: 'A linked legacy code-bug row exists, but no matching primary incident id was found.',
        }
  }

  const exclusionIndexes = exclusionsByPoc.get(poc) ?? []
  if (exclusionIndexes.length > 0) {
    return {
      status: 'excluded',
      exclusionIds: exclusionIndexes.map((index) => `exclusion:${index + 1}`),
      reason: 'The source has at least one explicit exclusion adjudication and no linked dataset row.',
    }
  }

  return {
    status: 'unresolved',
    reason: 'The source snapshot has no dataset row or explicit exclusion adjudication.',
  }
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

const dfhlCandidates = allDfhlPaths.map((poc) => {
  const otherMatch = otherIdentifierByPoc.get(poc)
  const directRows = directDfhlRows.get(poc) ?? []
  const rows = otherMatch ? rowsForOtherIdentifier(otherMatch) : directRows
  const relatedExclusionIds = (exclusionsByPoc.get(poc) ?? []).map(
    (index) => `exclusion:${index + 1}`,
  )
  const coverage = otherMatch
    ? {
        kind: 'other-identifier',
        legacyDatasetFile: otherMatch.datasetFile,
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
    ...(relatedExclusionIds.length > 0 ? { relatedExclusionIds } : {}),
    ...(rows.length > 0
      ? { matchedRows: rows.map(legacyCoordinates).sort((a, b) => compareStrings(a.file, b.file)) }
      : {}),
    disposition: dfhlDisposition(rows, poc),
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
  const exactSourceRows = sourceRows.filter((row) => {
    if (row.date.slice(0, 10) !== web.date) return false
    return [row.protocolName, row.protocolSlug, row.name]
      .filter(Boolean)
      .some((name) => normalizedName(name) === candidateName)
  })
  const incidentIds = unique(exactSourceRows.flatMap((row) => row.incidentIds)).sort()
  const disposition =
    incidentIds.length === 1
      ? {
          status: 'included',
          incidentIds,
          reason: 'Exact normalized project name and UTC date match one primary incident.',
        }
      : {
          status: 'unresolved',
          reason:
            incidentIds.length > 1
              ? 'Exact name/date matching is ambiguous across multiple primary incidents.'
              : exactSourceRows.length > 0
                ? 'An exact legacy name/date match exists, but it is not admitted to the primary dataset.'
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
    ...(exactSourceRows.length > 0
      ? { matchedRows: exactSourceRows.map(legacyCoordinates) }
      : {}),
    disposition,
  }
})

const exclusionCandidates = exclusions.map((entry, index) => ({
  id: `exclusion:${index + 1}`,
  source: {
    kind: 'exclusion',
    file: relative(root, exclusionsPath),
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
    status: 'excluded',
    reason: entry.reason,
  },
}))

const legacyIdCounts = new Map()
const legacyCandidates = legacyRows
  .filter(
    (row) => row.category !== 'code-bug' || row.measurementStatus === 'SCOPE_ONLY',
  )
  .map((row) => {
    const date = row.date.slice(0, 10)
    const baseId = `legacy:${row.protocolSlug}:${date}:${slug(row.name)}`
    const ordinal = (legacyIdCounts.get(baseId) ?? 0) + 1
    legacyIdCounts.set(baseId, ordinal)
    const id = ordinal === 1 ? baseId : `${baseId}:${ordinal}`
    const codeBugPending = row.category === 'code-bug'

    return {
      id,
      source: {
        kind: 'legacy',
        file: relative(root, legacyV1Path),
        entryIndex: row.contextIndex,
        original: row.originalSource,
      },
      legacyRecord: {
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
      disposition: codeBugPending
        ? {
            status: 'pending',
            reason: 'The legacy row is classified as a code bug but was scope-only and has no primary measurement.',
          }
        : {
            status: 'out-of-scope',
            reason: `The legacy category ${row.category} is outside the primary onchain code-bug dataset.`,
          },
    }
  })

const candidates = [
  ...dfhlCandidates,
  ...webCandidates,
  ...exclusionCandidates,
  ...legacyCandidates,
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

const result = {
  $schema: '../schema/candidate.schema.json',
  schemaVersion: 1,
  description:
    'Deterministic provenance ledger for source candidates, explicit exclusions, and legacy rows outside the primary dataset. Entries from different source inventories may refer to the same real-world event; that overlap is retained rather than guessed away.',
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
    exclusions: {
      file: relative(root, exclusionsPath),
      sha256: sha256(readFileSync(exclusionsPath)),
    },
    legacyV1: {
      file: relative(root, legacyV1Path),
      rows: legacyV1.rows.length,
      sha256: sha256(readFileSync(legacyV1Path)),
      originalSource: legacyV1.source,
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
