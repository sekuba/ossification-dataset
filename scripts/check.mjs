/**
 * Dependency-free release validator for the v2 incident interface.
 *
 * JSON Schema owns document shape. This script implements the schema keywords
 * used by schema/incident.schema.json, then adds invariants spanning fields,
 * files, records, the research ledger, and generated distribution artifacts.
 * Every reported issue is release-blocking; unresolved research candidates are
 * counted but are not themselves an error.
 *
 *   node scripts/check.mjs
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { buildArtifacts, ROOT, sha256 } from './build.mjs'

const INCIDENT_ID = /^eip155:([1-9][0-9]*):(0x[0-9a-f]{64})$/
const LEGACY_ID = /^legacy:/
const REVIEWED_FAILURE_ID = /^failure:[a-z0-9]+(?:[-:][a-z0-9]+)*$/
const ALLOWED_CHANGE_KINDS = new Set(['deployment', 'implementation-change', 'module-change'])
const CANDIDATE_STATUSES = new Set(['included', 'excluded', 'out-of-scope', 'pending', 'unresolved'])
const CANDIDATE_SOURCE_KINDS = new Set(['defihacklabs', 'web-list', 'exclusion', 'legacy'])
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  '$schema', '$id', '$ref', '$defs', 'title', 'description', 'default', 'examples',
  'type', 'const', 'enum', 'format', 'pattern', 'minLength', 'maxLength',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
  'properties', 'patternProperties', 'additionalProperties', 'required', 'minProperties', 'maxProperties',
  'items', 'minItems', 'maxItems', 'uniqueItems',
  'allOf', 'anyOf', 'oneOf', 'not', 'if', 'then', 'else',
])

function jsonEqual(a, b) {
  return JSON.stringify(a) === JSON.stringify(b)
}

function typeMatches(value, type) {
  switch (type) {
    case 'null': return value === null
    case 'array': return Array.isArray(value)
    case 'object': return value !== null && typeof value === 'object' && !Array.isArray(value)
    case 'integer': return Number.isSafeInteger(value)
    case 'number': return typeof value === 'number' && Number.isFinite(value)
    case 'string': return typeof value === 'string'
    case 'boolean': return typeof value === 'boolean'
    default: throw new Error(`schema uses unsupported type ${JSON.stringify(type)}`)
  }
}

function pointerPart(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1')
}

function resolveRef(rootSchema, ref) {
  if (!ref.startsWith('#/')) throw new Error(`only local JSON Schema references are supported: ${ref}`)
  let current = rootSchema
  for (const raw of ref.slice(2).split('/')) {
    const key = raw.replaceAll('~1', '/').replaceAll('~0', '~')
    current = current?.[key]
  }
  if (current === undefined) throw new Error(`unresolved JSON Schema reference: ${ref}`)
  return current
}

function assertSupportedSchema(schema, at = '$') {
  if (typeof schema === 'boolean') return
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(key))
      throw new Error(`unsupported JSON Schema keyword at ${at}: ${key}`)
  }
  for (const [key, child] of Object.entries(schema.$defs ?? {}))
    assertSupportedSchema(child, `${at}/$defs/${pointerPart(key)}`)
  for (const [key, child] of Object.entries(schema.properties ?? {}))
    assertSupportedSchema(child, `${at}/properties/${pointerPart(key)}`)
  for (const [key, child] of Object.entries(schema.patternProperties ?? {}))
    assertSupportedSchema(child, `${at}/patternProperties/${pointerPart(key)}`)
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object')
    assertSupportedSchema(schema.additionalProperties, `${at}/additionalProperties`)
  if (schema.items && !Array.isArray(schema.items)) assertSupportedSchema(schema.items, `${at}/items`)
  for (const keyword of ['allOf', 'anyOf', 'oneOf']) {
    for (const [index, child] of (schema[keyword] ?? []).entries())
      assertSupportedSchema(child, `${at}/${keyword}/${index}`)
  }
  for (const keyword of ['not', 'if', 'then', 'else']) {
    if (schema[keyword]) assertSupportedSchema(schema[keyword], `${at}/${keyword}`)
  }
}

function checkFormat(value, format) {
  if (typeof value !== 'string') return true
  if (format === 'uri') {
    try {
      const url = new URL(value)
      return Boolean(url.protocol)
    } catch {
      return false
    }
  }
  if (format === 'date-time') {
    return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && !Number.isNaN(Date.parse(value))
  }
  throw new Error(`schema uses unsupported format ${JSON.stringify(format)}`)
}

/** Validate an instance using the JSON Schema subset used by this repository. */
export function validateSchema(instance, schema, rootSchema = schema, at = '$', errors = []) {
  if (schema === true) return errors
  if (schema === false) {
    errors.push(`${at}: rejected by false schema`)
    return errors
  }
  if (schema.$ref) {
    validateSchema(instance, resolveRef(rootSchema, schema.$ref), rootSchema, at, errors)
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type]
    if (!types.some((type) => typeMatches(instance, type))) {
      errors.push(`${at}: expected ${types.join(' or ')}`)
      return errors
    }
  }
  if (schema.const !== undefined && !jsonEqual(instance, schema.const))
    errors.push(`${at}: expected constant ${JSON.stringify(schema.const)}`)
  if (schema.enum && !schema.enum.some((value) => jsonEqual(instance, value)))
    errors.push(`${at}: expected one of ${schema.enum.map((value) => JSON.stringify(value)).join(', ')}`)

  if (typeof instance === 'string') {
    if (schema.minLength !== undefined && [...instance].length < schema.minLength)
      errors.push(`${at}: shorter than minLength ${schema.minLength}`)
    if (schema.maxLength !== undefined && [...instance].length > schema.maxLength)
      errors.push(`${at}: longer than maxLength ${schema.maxLength}`)
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(instance))
      errors.push(`${at}: does not match ${JSON.stringify(schema.pattern)}`)
    if (schema.format !== undefined && !checkFormat(instance, schema.format))
      errors.push(`${at}: invalid ${schema.format}`)
  }

  if (typeof instance === 'number' && Number.isFinite(instance)) {
    if (schema.minimum !== undefined && instance < schema.minimum)
      errors.push(`${at}: ${instance} is below minimum ${schema.minimum}`)
    if (schema.maximum !== undefined && instance > schema.maximum)
      errors.push(`${at}: ${instance} is above maximum ${schema.maximum}`)
    if (schema.exclusiveMinimum !== undefined && instance <= schema.exclusiveMinimum)
      errors.push(`${at}: ${instance} is not above exclusiveMinimum ${schema.exclusiveMinimum}`)
    if (schema.exclusiveMaximum !== undefined && instance >= schema.exclusiveMaximum)
      errors.push(`${at}: ${instance} is not below exclusiveMaximum ${schema.exclusiveMaximum}`)
  }

  if (Array.isArray(instance)) {
    if (schema.minItems !== undefined && instance.length < schema.minItems)
      errors.push(`${at}: has fewer than ${schema.minItems} items`)
    if (schema.maxItems !== undefined && instance.length > schema.maxItems)
      errors.push(`${at}: has more than ${schema.maxItems} items`)
    if (schema.uniqueItems) {
      for (let index = 0; index < instance.length; index++) {
        if (instance.slice(0, index).some((value) => jsonEqual(value, instance[index]))) {
          errors.push(`${at}/${index}: duplicate array item`)
          break
        }
      }
    }
    if (schema.items && !Array.isArray(schema.items)) {
      for (const [index, value] of instance.entries())
        validateSchema(value, schema.items, rootSchema, `${at}/${index}`, errors)
    }
  }

  if (instance !== null && typeof instance === 'object' && !Array.isArray(instance)) {
    const keys = Object.keys(instance)
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(instance, required)) errors.push(`${at}: missing required property ${JSON.stringify(required)}`)
    }
    if (schema.minProperties !== undefined && keys.length < schema.minProperties)
      errors.push(`${at}: has fewer than ${schema.minProperties} properties`)
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties)
      errors.push(`${at}: has more than ${schema.maxProperties} properties`)

    const matched = new Set()
    for (const [key, childSchema] of Object.entries(schema.properties ?? {})) {
      if (!Object.hasOwn(instance, key)) continue
      matched.add(key)
      validateSchema(instance[key], childSchema, rootSchema, `${at}/${pointerPart(key)}`, errors)
    }
    for (const [pattern, childSchema] of Object.entries(schema.patternProperties ?? {})) {
      const regex = new RegExp(pattern, 'u')
      for (const key of keys) {
        if (!regex.test(key)) continue
        matched.add(key)
        validateSchema(instance[key], childSchema, rootSchema, `${at}/${pointerPart(key)}`, errors)
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of keys) if (!matched.has(key)) errors.push(`${at}: unknown property ${JSON.stringify(key)}`)
    } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      for (const key of keys) {
        if (!matched.has(key))
          validateSchema(instance[key], schema.additionalProperties, rootSchema, `${at}/${pointerPart(key)}`, errors)
      }
    }
  }

  for (const child of schema.allOf ?? []) validateSchema(instance, child, rootSchema, at, errors)
  if (schema.anyOf) {
    const matches = schema.anyOf.filter((child) => validateSchema(instance, child, rootSchema, at, []).length === 0)
    if (matches.length === 0) errors.push(`${at}: does not match any anyOf branch`)
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((child) => validateSchema(instance, child, rootSchema, at, []).length === 0)
    if (matches.length !== 1) errors.push(`${at}: matches ${matches.length} oneOf branches (expected exactly 1)`)
  }
  if (schema.not && validateSchema(instance, schema.not, rootSchema, at, []).length === 0)
    errors.push(`${at}: matches forbidden not schema`)
  if (schema.if) {
    const conditionMatches = validateSchema(instance, schema.if, rootSchema, at, []).length === 0
    if (conditionMatches && schema.then) validateSchema(instance, schema.then, rootSchema, at, errors)
    if (!conditionMatches && schema.else) validateSchema(instance, schema.else, rootSchema, at, errors)
  }
  return errors
}

function walkJsonFiles(directory, relativeTo = directory) {
  if (!existsSync(directory)) return []
  const files = []
  for (const entry of readdirSync(directory).sort()) {
    const absolute = path.join(directory, entry)
    if (statSync(absolute).isDirectory()) files.push(...walkJsonFiles(absolute, relativeTo))
    else if (entry.endsWith('.json'))
      files.push({ absolute, relative: path.relative(relativeTo, absolute).split(path.sep).join('/') })
  }
  return files
}

function parseJson(file, label, errors) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    errors.push(`${label}: invalid JSON: ${error.message}`)
    return null
  }
}

function digestFiles(root, files) {
  const hash = createHash('sha256')
  for (const file of [...files].sort()) {
    hash.update(`${path.relative(root, file).split(path.sep).join('/')}\u0000`)
    hash.update(readFileSync(file))
    hash.update('\u0000')
  }
  return hash.digest('hex')
}

function validSafeChainId(value) {
  return Number.isSafeInteger(value) && value >= 1
}

function sourceTransactionKeys(incident) {
  return new Set(
    (incident.sources ?? [])
      .filter((source) => source.type === 'onchain-transaction')
      .map((source) => `${source.chainId}:${source.transactionHash}`),
  )
}

function compareTransactionOrder(a, b) {
  if (a?.blockNumber === null || a?.transactionIndex === null ||
      b?.blockNumber === null || b?.transactionIndex === null) return null
  return a.blockNumber - b.blockNumber || a.transactionIndex - b.transactionIndex
}

function verifyReviewSources(label, reviewSourceIds, requiredClaims, sourceById, errors) {
  const supported = new Set()
  for (const sourceId of reviewSourceIds ?? []) {
    const source = sourceById.get(sourceId)
    if (!source) {
      errors.push(`${label}: reviewSourceIds cites unknown source id ${sourceId}`)
      continue
    }
    if (source.type !== 'review-note') {
      errors.push(`${label}: reviewSourceIds source ${sourceId} is not a review-note`)
      continue
    }
    if (!source.reviewer)
      errors.push(`${label}: linked review note ${sourceId} has no reviewer`)
    if (!source.reviewedAt)
      errors.push(`${label}: linked review note ${sourceId} has no reviewedAt`)
    for (const claim of source.supports ?? []) supported.add(claim)
  }
  for (const claim of requiredClaims) {
    if (!supported.has(claim))
      errors.push(`${label}: linked review notes do not attest ${claim}`)
  }
}

function verifyIncident(record, state, errors) {
  const incident = record.incident
  const label = record.path
  const idMatch = INCIDENT_ID.exec(incident.id ?? '')
  const chainId = incident.incident?.chainId
  const exploit = incident.incident?.exploit
  const incidentReviewed = incident.verification?.tier === 'reviewed'
  if (!validSafeChainId(chainId)) errors.push(`${label}: incident.chainId must be a positive safe EIP-155 integer`)
  if (idMatch) {
    if (Number(idMatch[1]) !== chainId)
      errors.push(`${label}: id chain ${idMatch[1]} does not equal incident.chainId ${chainId}`)
    if (idMatch[2] !== exploit?.transactionHash)
      errors.push(`${label}: id transaction hash does not equal incident.exploit.transactionHash`)
  }

  const basename = path.posix.basename(record.relative, '.json')
  const parent = path.posix.dirname(record.relative)
  if (basename !== exploit?.transactionHash)
    errors.push(`${label}: filename must equal the exploit transaction hash (${exploit?.transactionHash}.json)`)
  if (parent !== String(chainId))
    errors.push(`${label}: incident must be stored under incidents/${chainId}/`)

  if (state.incidentIds.has(incident.id))
    errors.push(`${label}: duplicate incident id also appears in ${state.incidentIds.get(incident.id)}`)
  else state.incidentIds.set(incident.id, label)
  for (const candidateId of incident.discovery ?? [])
    state.discoveryRefs.set(candidateId, [...(state.discoveryRefs.get(candidateId) ?? []), label])
  const txKey = `${chainId}:${exploit?.transactionHash}`
  if (state.exploitTransactions.has(txKey))
    errors.push(`${label}: exploit transaction also appears in ${state.exploitTransactions.get(txKey)}`)
  else state.exploitTransactions.set(txKey, label)

  const sourceIds = new Set()
  const sourceById = new Map()
  for (const [index, source] of (incident.sources ?? []).entries()) {
    const sourceLabel = `${label}: sources[${index}]`
    if (sourceIds.has(source.id)) errors.push(`${sourceLabel}: duplicate source id ${source.id}`)
    sourceIds.add(source.id)
    sourceById.set(source.id, source)
    if (source.type === 'onchain-transaction' && source.chainId !== chainId)
      errors.push(`${sourceLabel}: chainId ${source.chainId} does not equal incident chainId ${chainId}`)
    if (source.type === 'source-code' && !/^[0-9a-f]{40}$/.test(source.commit ?? ''))
      errors.push(`${sourceLabel}: source-code evidence must pin a full 40-character commit`)
  }
  const transactionKeys = sourceTransactionKeys(incident)
  if (!transactionKeys.has(txKey))
    errors.push(`${label}: sources must include the exact exploit transaction on chain ${chainId}`)
  else if (!(incident.sources.find((source) =>
    source.type === 'onchain-transaction' && source.chainId === chainId &&
    source.transactionHash === exploit.transactionHash)?.supports ?? []).includes('incident-anchor'))
    errors.push(`${label}: exact exploit transaction source must declare incident-anchor support`)

  const realizedAt = incident.loss?.realizedAt
  if (realizedAt !== undefined && realizedAt < exploit?.timestamp)
    errors.push(`${label}: loss.realizedAt precedes the incident anchor; the campaign cannot end before it starts`)
  const valuationLimit = Math.max(exploit?.timestamp ?? 0, realizedAt ?? 0)

  const usd = incident.loss?.usd
  if (usd) {
    if (incidentReviewed && usd.sourceIds.length === 0) errors.push(`${label}: reviewed loss.usd must cite loss evidence`)
    for (const sourceId of usd.sourceIds) {
      if (!sourceIds.has(sourceId)) errors.push(`${label}: loss.usd cites unknown source id ${sourceId}`)
      else if (!(incident.sources.find((source) => source.id === sourceId)?.supports ?? []).includes('loss'))
        errors.push(`${label}: loss.usd source ${sourceId} does not declare loss support`)
    }
    if (usd.valuationTimestamp > valuationLimit)
      errors.push(
        `${label}: loss valuationTimestamp is after the incident anchor and any declared loss.realizedAt; ` +
          'document later repricing outside the primary value',
      )
  }
  const minimumUsd = incident.loss?.minimumUsd
  if (usd && minimumUsd) errors.push(`${label}: use loss.usd or loss.minimumUsd, not both`)
  if (minimumUsd) {
    if (minimumUsd.sourceIds.length === 0) errors.push(`${label}: loss.minimumUsd must cite inclusion evidence`)
    for (const sourceId of minimumUsd.sourceIds) {
      if (!sourceIds.has(sourceId)) errors.push(`${label}: loss.minimumUsd cites unknown source id ${sourceId}`)
      else if (!(incident.sources.find((source) => source.id === sourceId)?.supports ?? []).includes('loss'))
        errors.push(`${label}: loss.minimumUsd source ${sourceId} does not declare loss support`)
    }
  }
  for (const [assetIndex, asset] of (incident.loss?.assets ?? []).entries()) {
    if (incidentReviewed && asset.sourceIds.length === 0)
      errors.push(`${label}: reviewed loss.assets[${assetIndex}] must cite loss evidence`)
    if (asset.valuation?.timestamp > valuationLimit)
      errors.push(
        `${label}: loss.assets[${assetIndex}].valuation.timestamp is after the incident anchor and any ` +
          'declared loss.realizedAt; incident-price evidence must be contemporaneous with the loss or earlier',
      )
    const assetSourceIds = [
      ...(asset.sourceIds ?? []),
      ...(asset.valuation?.sourceIds ?? []),
    ]
    for (const sourceId of assetSourceIds) {
      if (!sourceIds.has(sourceId)) errors.push(`${label}: loss.assets[${assetIndex}] cites unknown source id ${sourceId}`)
      else if (!(incident.sources.find((source) => source.id === sourceId)?.supports ?? []).includes('loss'))
        errors.push(`${label}: loss.assets[${assetIndex}] source ${sourceId} does not declare loss support`)
    }
  }

  if (incidentReviewed) {
    if (incident.loss.kind === 'legacy-unspecified')
      errors.push(`${label}: reviewed incident requires a reviewed loss kind`)
    if (usd?.method === 'legacy-unspecified')
      errors.push(`${label}: reviewed incident requires a reviewed USD valuation method`)
    if (minimumUsd?.basis === 'legacy-inclusion-rule')
      errors.push(`${label}: reviewed incident cannot rely on the legacy inclusion rule`)
    if (!['high', 'medium'].includes(incident.loss.confidence))
      errors.push(`${label}: reviewed incident requires high or medium loss confidence`)
    verifyReviewSources(
      `${label}: verification`,
      incident.verification.reviewSourceIds,
      ['incident-anchor', 'root-cause', 'loss'],
      sourceById,
      errors,
    )
  }

  const localPairs = new Set()
  const targetIds = new Set()
  for (const [index, target] of (incident.targets ?? []).entries()) {
    const targetLabel = `${label}: targets[${index}]`
    const deployment = target.deployment
    const change = target.lastCodeChange
    const targetTier = target.verification?.tier
    const targetEligible = target.verification?.curveEligible === true
    const eligible = incidentReviewed && targetTier === 'reviewed' && targetEligible
    if (targetIds.has(target.id)) errors.push(`${targetLabel}: duplicate target id ${target.id}`)
    targetIds.add(target.id)
    if (target.codeAgeSeconds !== exploit.timestamp - change.timestamp)
      errors.push(
        `${targetLabel}: codeAgeSeconds ${target.codeAgeSeconds} != incident.timestamp - lastCodeChange.timestamp ` +
          `(${exploit.timestamp - change.timestamp})`,
      )
    if (change.timestamp < deployment.timestamp)
      errors.push(`${targetLabel}: last code change precedes target deployment`)
    if (change.timestamp > exploit.timestamp)
      errors.push(`${targetLabel}: last code change occurs after exploit`)
    if (deployment.blockNumber !== null && exploit.blockNumber !== null && deployment.blockNumber > exploit.blockNumber)
      errors.push(`${targetLabel}: deployment block is after exploit block`)
    if (change.blockNumber !== null && exploit.blockNumber !== null && change.blockNumber > exploit.blockNumber)
      errors.push(`${targetLabel}: last-code-change block is after exploit block`)
    const deploymentVsChange = compareTransactionOrder(deployment, change)
    if (deploymentVsChange !== null && deploymentVsChange > 0)
      errors.push(`${targetLabel}: deployment transaction is ordered after last code change`)
    const changeVsExploit = compareTransactionOrder(change, exploit)
    if (changeVsExploit !== null && changeVsExploit >= 0)
      errors.push(`${targetLabel}: last code change transaction does not precede exploit transaction`)
    const deploymentVsExploit = compareTransactionOrder(deployment, exploit)
    if (deploymentVsExploit !== null && deploymentVsExploit >= 0)
      errors.push(`${targetLabel}: deployment transaction does not precede exploit transaction`)

    if (change.kind === 'deployment') {
      for (const key of ['timestamp', 'blockNumber', 'transactionHash', 'transactionIndex']) {
        if (deployment[key] !== change[key])
          errors.push(`${targetLabel}: deployment-basis lastCodeChange.${key} differs from deployment.${key}`)
      }
      if (change.mechanism?.type !== 'deployment')
        errors.push(`${targetLabel}: deployment-basis lastCodeChange must use deployment mechanism`)
      else if (change.mechanism.address !== target.executionAddress)
        errors.push(`${targetLabel}: deployment mechanism address must equal executionAddress`)
    }
    if (target.relationship === 'direct' && target.codeArtifact?.address &&
        target.codeArtifact.address !== target.executionAddress)
      errors.push(`${targetLabel}: direct target code artifact address must equal executionAddress`)
    if ((incident.incident?.attackerAddresses ?? []).includes(target.executionAddress))
      errors.push(`${targetLabel}: executionAddress is an attacker address`)
    if (deployment.creatorAddress && (incident.incident?.attackerAddresses ?? []).includes(deployment.creatorAddress))
      errors.push(`${targetLabel}: victim code was deployed by an attacker address`)

    if (target.codeArtifact?.codeHash) {
      const pair = JSON.stringify([target.codeArtifact.codeHash, target.failureModeId])
      if (localPairs.has(pair))
        errors.push(`${targetLabel}: duplicate (codeArtifact.codeHash, failureModeId) within one incident`)
      localPairs.add(pair)
    }

    for (const [field, claim] of [
      ['identitySourceIds', 'target-identity'],
      ['codeHistorySourceIds', 'code-history'],
    ]) {
      for (const sourceId of target.evidence?.[field] ?? []) {
        const source = sourceById.get(sourceId)
        if (!source) errors.push(`${targetLabel}: evidence.${field} cites unknown source id ${sourceId}`)
        else if (!source.supports.includes(claim))
          errors.push(`${targetLabel}: evidence.${field} source ${sourceId} does not declare ${claim} support`)
      }
    }

    if (targetTier === 'reviewed') {
      verifyReviewSources(
        `${targetLabel}: verification`,
        target.verification.reviewSourceIds,
        ['target-identity', 'code-history'],
        sourceById,
        errors,
      )
    }

    if (targetEligible && !incidentReviewed)
      errors.push(`${targetLabel}: target curve eligibility requires reviewed incident classification and loss`)
    if (targetEligible && targetTier !== 'reviewed')
      errors.push(`${targetLabel}: target curve eligibility requires reviewed target verification`)

    if (eligible) {
      if (!usd || usd.amount < 1_000)
        errors.push(`${targetLabel}: curve eligibility requires evidenced loss.usd.amount >= 1000`)
      if (!ALLOWED_CHANGE_KINDS.has(change.kind))
        errors.push(`${targetLabel}: curve cannot use ${change.kind} as executable-code age`)
      if (LEGACY_ID.test(target.failureModeId) || !REVIEWED_FAILURE_ID.test(target.failureModeId))
        errors.push(`${targetLabel}: curve failureModeId must use the reviewed failure:<namespace> form`)
      if (!target.codeArtifact?.address || !target.codeArtifact?.codeHash)
        errors.push(`${targetLabel}: curve eligibility requires an address and code hash for the code artifact`)
      if ((target.evidence?.identitySourceIds ?? []).length === 0 ||
          (target.evidence?.codeHistorySourceIds ?? []).length === 0)
        errors.push(`${targetLabel}: curve eligibility requires target-specific identity and code-history evidence`)
      for (const [anchorName, anchor] of [['deployment', deployment], ['lastCodeChange', change]]) {
        if (anchor.blockNumber === null || anchor.transactionHash === null)
          errors.push(`${targetLabel}: curve eligibility requires a complete ${anchorName} anchor`)
        else {
          const anchorSource = incident.sources.find((source) =>
            source.type === 'onchain-transaction' && source.chainId === chainId &&
            source.transactionHash === anchor.transactionHash)
          if (!anchorSource)
            errors.push(`${targetLabel}: ${anchorName} transaction must have an onchain source entry`)
          else if (!anchorSource.supports.includes('code-history'))
            errors.push(`${targetLabel}: ${anchorName} transaction source must declare code-history support`)
          else if (!(target.evidence?.codeHistorySourceIds ?? []).includes(anchorSource.id))
            errors.push(`${targetLabel}: ${anchorName} transaction source must be linked in target evidence`)
        }
      }
      if (!deployment.creatorAddress) errors.push(`${targetLabel}: curve eligibility requires creatorAddress`)
      if (change.transactionHash === exploit.transactionHash)
        errors.push(`${targetLabel}: attacker-transaction code changes cannot define pre-exploit code age`)
      if (change.mechanism?.type === 'event' && change.mechanism.codeAddressLocation === null)
        errors.push(`${targetLabel}: eligible event change requires codeAddressLocation`)
    } else if (targetTier !== 'provisional') {
      if ([deployment.blockNumber, deployment.transactionHash, deployment.transactionIndex, deployment.creatorAddress,
        change.blockNumber, change.transactionHash, change.transactionIndex].some((value) => value === null))
        errors.push(`${targetLabel}: non-provisional verification requires complete anchors`)
    }
    if (targetTier === 'reviewed' && change.mechanism?.type === 'event' && change.logIndex === null)
      errors.push(`${targetLabel}: event-based reviewed change requires logIndex`)
  }

  const legacy = incident.verification?.legacy
  if (legacy) {
    const key = `${legacy.originalFile}\u0000${legacy.originalIncidentIndex}`
    const rawRow = state.legacyRows.get(key)
    if (!rawRow)
      errors.push(`${label}: legacy coordinate does not resolve in research/raw/legacy-v1.json`)
    else {
      if (rawRow.incident?.date !== legacy.date)
        errors.push(`${label}: legacy.date does not equal the snapshot row date`)
      const reanchored = rawRow.incident?.exploitTx?.toLowerCase() !== exploit.transactionHash
      if (reanchored && legacy.reanchored !== true)
        errors.push(`${label}: incident anchor differs from the snapshot row; set legacy.reanchored`)
      if (!reanchored && legacy.reanchored === true)
        errors.push(`${label}: legacy.reanchored is set but the incident anchor is unchanged`)
      if (rawRow.protocol?.slug !== incident.protocol.slug)
        errors.push(`${label}: legacy coordinate resolves to a different protocol slug`)
    }
  }
}

function validateCandidates(root, incidentIds, discoveryRefs, errors, notes) {
  const candidatePath = path.join(root, 'research', 'candidates.json')
  if (!existsSync(candidatePath)) return
  const document = parseJson(candidatePath, 'research/candidates.json', errors)
  if (!document) return
  const candidateSchemaPath = path.join(root, 'schema', 'candidate.schema.json')
  const candidateSchema = existsSync(candidateSchemaPath)
    ? parseJson(candidateSchemaPath, 'schema/candidate.schema.json', errors)
    : null
  if (!candidateSchema) errors.push('schema/candidate.schema.json: required when research/candidates.json exists')
  else {
    try {
      assertSupportedSchema(candidateSchema)
      for (const error of validateSchema(document, candidateSchema))
        errors.push(`research/candidates.json: schema ${error}`)
    } catch (error) {
      errors.push(`schema/candidate.schema.json: ${error.message}`)
    }
  }
  if (document.schemaVersion !== 1) errors.push('research/candidates.json: schemaVersion must equal 1')
  if (!Array.isArray(document.candidates)) {
    errors.push('research/candidates.json: candidates must be an array')
    return
  }

  const ids = new Set()
  const exclusionIds = new Set(
    document.candidates
      .filter((candidate) => candidate.source?.kind === 'exclusion')
      .map((candidate) => candidate.id),
  )
  const counts = {}
  const sourceCounts = {}
  const dfhlCoverageCounts = {}
  const sortedIds = document.candidates.map((candidate) => candidate.id)
  if (!jsonEqual(sortedIds, [...sortedIds].sort()))
    errors.push('research/candidates.json: candidates must be sorted by id')
  for (const [index, candidate] of document.candidates.entries()) {
    const label = `research/candidates.json: candidates[${index}]`
    if (typeof candidate.id !== 'string' || candidate.id.length === 0) errors.push(`${label}: missing stable id`)
    else if (ids.has(candidate.id)) errors.push(`${label}: duplicate id ${candidate.id}`)
    else ids.add(candidate.id)
    if (!candidate.source || typeof candidate.source !== 'object') errors.push(`${label}: missing source coordinates`)
    else if (!CANDIDATE_SOURCE_KINDS.has(candidate.source.kind))
      errors.push(`${label}: invalid source kind ${JSON.stringify(candidate.source.kind)}`)
    else sourceCounts[candidate.source.kind] = (sourceCounts[candidate.source.kind] ?? 0) + 1
    const disposition = candidate.disposition
    if (!disposition || !CANDIDATE_STATUSES.has(disposition.status)) {
      errors.push(`${label}: invalid disposition status ${JSON.stringify(disposition?.status)}`)
      continue
    }
    counts[disposition.status] = (counts[disposition.status] ?? 0) + 1
    const incidentRefs = disposition.incidentIds ?? candidate.incidentIds ?? []
    if (disposition.status === 'included' && incidentRefs.length === 0)
      errors.push(`${label}: included candidate must reference at least one incident id`)
    if (disposition.status !== 'included' && (typeof disposition.reason !== 'string' || !disposition.reason))
      errors.push(`${label}: non-included candidate must explain its disposition`)
    for (const incidentId of incidentRefs) {
      if (!incidentIds.has(incidentId)) errors.push(`${label}: dangling incident id ${incidentId}`)
    }
    for (const exclusionId of [
      ...(candidate.relatedExclusionIds ?? []),
      ...(disposition.exclusionIds ?? []),
    ]) {
      if (!exclusionIds.has(exclusionId)) errors.push(`${label}: dangling exclusion id ${exclusionId}`)
    }
    for (const matchedRow of candidate.matchedRows ?? []) {
      if (matchedRow.file?.startsWith('incidents/') && !existsSync(path.join(root, matchedRow.file)))
        errors.push(`${label}: matched incident file does not exist: ${matchedRow.file}`)
    }
    if (candidate.source?.kind === 'defihacklabs') {
      if (!/^[0-9a-f]{40}$/.test(candidate.source.commit ?? ''))
        errors.push(`${label}: DeFiHackLabs source must pin a full 40-character commit`)
      if (typeof candidate.source.path !== 'string' || !candidate.source.path)
        errors.push(`${label}: DeFiHackLabs source must include an exact path`)
      const coverage = candidate.coverage?.kind
      if (!['direct-reference', 'other-identifier', 'no-dataset-row'].includes(coverage))
        errors.push(`${label}: invalid DeFiHackLabs coverage kind ${JSON.stringify(coverage)}`)
      else dfhlCoverageCounts[coverage] = (dfhlCoverageCounts[coverage] ?? 0) + 1
    }
  }

  for (const [candidateId, labels] of discoveryRefs) {
    if (!ids.has(candidateId))
      errors.push(`${labels.join(', ')}: discovery cites unknown research candidate ${candidateId}`)
  }

  if (document.counts?.total !== document.candidates.length)
    errors.push(`research/candidates.json: counts.total does not equal ${document.candidates.length}`)
  for (const [status, count] of Object.entries(counts)) {
    if (document.counts?.byDisposition?.[status] !== count)
      errors.push(
        `research/candidates.json: counts.byDisposition.${status} ` +
          `${document.counts?.byDisposition?.[status]} != ${count}`,
      )
  }
  for (const [status, count] of Object.entries(document.counts?.byDisposition ?? {})) {
    if ((counts[status] ?? 0) !== count)
      errors.push(`research/candidates.json: unexpected/incorrect disposition count ${status}=${count}`)
  }
  for (const [kind, count] of Object.entries(sourceCounts)) {
    if (document.counts?.bySource?.[kind] !== count)
      errors.push(`research/candidates.json: counts.bySource.${kind} ${document.counts?.bySource?.[kind]} != ${count}`)
  }
  for (const [kind, count] of Object.entries(document.counts?.bySource ?? {})) {
    if ((sourceCounts[kind] ?? 0) !== count)
      errors.push(`research/candidates.json: unexpected/incorrect source count ${kind}=${count}`)
  }
  const dfhlExpectedKeys = {
    'direct-reference': 'directReference',
    'other-identifier': 'otherIdentifier',
    'no-dataset-row': 'noDatasetRow',
  }
  for (const [kind, field] of Object.entries(dfhlExpectedKeys)) {
    const count = dfhlCoverageCounts[kind] ?? 0
    if (document.counts?.defihacklabsCoverage?.[field] !== count)
      errors.push(
        `research/candidates.json: counts.defihacklabsCoverage.${field} ` +
          `${document.counts?.defihacklabsCoverage?.[field]} != ${count}`,
      )
  }
  if (document.counts?.defihacklabsCoverage?.total !== (sourceCounts.defihacklabs ?? 0))
    errors.push('research/candidates.json: defihacklabsCoverage.total does not equal DFHL source count')
  const unresolved = (counts.pending ?? 0) + (counts.unresolved ?? 0)
  if (unresolved > 0) notes.push(`research ledger: ${unresolved} pending/unresolved candidates (preserved, not reviewed)`)

  const coverageClaim = document.coverageComplete === true || document.generatedFrom?.coverageComplete === true
  if (coverageClaim && unresolved > 0)
    errors.push('research/candidates.json: cannot claim complete coverage with pending/unresolved candidates')

  const generated = document.generatedFrom ?? {}
  for (const field of ['defihacklabs', 'webList', 'exclusions', 'legacyV1']) {
    const relative = generated[field]?.file
    const absolute = typeof relative === 'string' ? path.resolve(root, relative) : ''
    const rawRoot = `${path.resolve(root, 'research', 'raw')}${path.sep}`
    if (!absolute.startsWith(rawRoot)) {
      errors.push(`research/candidates.json: generatedFrom.${field}.file must stay under research/raw/`)
      continue
    }
    if (!existsSync(absolute)) {
      errors.push(`research/candidates.json: generated input ${relative} does not exist`)
      continue
    }
    const actual = sha256(readFileSync(absolute))
    if (generated[field]?.sha256 !== actual)
      errors.push(`research/candidates.json: generatedFrom.${field}.sha256 is stale`)
  }
  const legacyV1Path = path.join(root, generated.legacyV1?.file ?? '')
  const legacyV1 = existsSync(legacyV1Path)
    ? parseJson(legacyV1Path, generated.legacyV1.file, errors)
    : null
  if (legacyV1) {
    if (legacyV1.source?.files !== 721 || legacyV1.source?.incidents !== 757 || legacyV1.rows?.length !== 757)
      errors.push('research/raw/legacy-v1.json: expected the complete 721-file / 757-row corpus')
    if (generated.legacyV1?.rows !== legacyV1.rows?.length)
      errors.push('research/candidates.json: generatedFrom.legacyV1.rows is stale')
    if (!jsonEqual(generated.legacyV1?.originalSource, legacyV1.source))
      errors.push('research/candidates.json: generatedFrom.legacyV1.originalSource is stale')
  }
  const primaryFiles = walkJsonFiles(path.join(root, 'incidents')).map((file) => file.absolute)
  if (generated.primaryIncidents?.files !== primaryFiles.length ||
      generated.primaryIncidents?.sha256 !== digestFiles(root, primaryFiles))
    errors.push('research/candidates.json: generatedFrom.primaryIncidents is stale')
}

function validateDistribution(root, errors) {
  const directory = path.join(root, 'dist', 'latest')
  if (!existsSync(directory)) return
  let expected
  try {
    expected = buildArtifacts(root)
  } catch (error) {
    errors.push(`dist/latest: cannot recompute distribution: ${error.message}`)
    return
  }
  for (const [artifact, schemaFile] of [
    ['curve', 'release-curve.schema.json'],
    ['manifest', 'release-manifest.schema.json'],
  ]) {
    const relative = `schema/${schemaFile}`
    const schema = parseJson(path.join(root, relative), relative, errors)
    if (!schema) continue
    try {
      assertSupportedSchema(schema)
      for (const error of validateSchema(expected.values[artifact], schema))
        errors.push(`dist/latest/${artifact}.json: schema ${error}`)
    } catch (error) {
      errors.push(`${relative}: ${error.message}`)
    }
  }
  for (const [name, contents] of Object.entries(expected.serialized)) {
    const output = path.join(directory, name)
    if (!existsSync(output)) {
      errors.push(`dist/latest/${name}: missing generated artifact`)
      continue
    }
    const actual = readFileSync(output, 'utf8')
    if (actual !== contents) errors.push(`dist/latest/${name}: stale or nondeterministic; run node scripts/build.mjs`)
  }

  const curve = expected.values.curve
  if (curve.ageKnots.length !== curve.observations.length)
    errors.push('dist/latest/curve.json: one age knot is required per curve observation')
  for (const [index, observation] of curve.observations.entries()) {
    if (curve.ageKnots[index] !== observation.codeAgeSeconds)
      errors.push(`dist/latest/curve.json: ageKnots[${index}] differs from its observation`)
    if (index > 0 && curve.ageKnots[index - 1] > curve.ageKnots[index])
      errors.push('dist/latest/curve.json: age knots are not sorted')
  }
  const manifest = expected.values.manifest
  for (const [name, metadata] of Object.entries(manifest.artifacts)) {
    const contents = expected.serialized[name]
    if (metadata.sha256 !== sha256(contents) || metadata.bytes !== Buffer.byteLength(contents))
      errors.push(`dist/latest/manifest.json: bad checksum metadata for ${name}`)
  }
}

export function checkDataset(root = ROOT) {
  const errors = []
  const notes = []
  const schemaPath = path.join(root, 'schema', 'incident.schema.json')
  const schema = parseJson(schemaPath, 'schema/incident.schema.json', errors)
  if (!schema) return { errors, notes, incidentCount: 0 }
  try {
    assertSupportedSchema(schema)
  } catch (error) {
    errors.push(`schema/incident.schema.json: ${error.message}`)
    return { errors, notes, incidentCount: 0 }
  }

  const directory = path.join(root, 'incidents')
  const files = walkJsonFiles(directory)
  if (files.length === 0) errors.push('incidents/: no JSON incident files found')
  const legacyPath = path.join(root, 'research', 'raw', 'legacy-v1.json')
  const legacyDocument = parseJson(legacyPath, 'research/raw/legacy-v1.json', errors)
  const legacyRows = new Map()
  for (const row of legacyDocument?.rows ?? []) {
    const key = `${row.source?.file}\u0000${row.source?.incidentIndex}`
    if (legacyRows.has(key))
      errors.push(`research/raw/legacy-v1.json: duplicate source coordinate ${key}`)
    else legacyRows.set(key, row)
  }
  const state = {
    incidentIds: new Map(),
    discoveryRefs: new Map(),
    exploitTransactions: new Map(),
    legacyRows,
  }
  for (const file of files) {
    const record = {
      ...file,
      path: `incidents/${file.relative}`,
      incident: parseJson(file.absolute, `incidents/${file.relative}`, errors),
    }
    if (!record.incident) continue
    for (const error of validateSchema(record.incident, schema)) errors.push(`${record.path}: schema ${error}`)
    // Cross-field checks assume required objects exist. Schema failures remain
    // useful on their own, so avoid a cascade of misleading runtime errors.
    if (record.incident.id && record.incident.incident?.exploit &&
        Array.isArray(record.incident.targets) && Array.isArray(record.incident.sources) &&
        record.incident.loss && record.incident.verification) {
      verifyIncident(record, state, errors)
    }
  }

  validateCandidates(root, state.incidentIds, state.discoveryRefs, errors, notes)
  validateDistribution(root, errors)
  return { errors, notes, incidentCount: files.length }
}

function main() {
  const result = checkDataset(ROOT)
  for (const note of result.notes) console.log(`NOTE: ${note}`)
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(`ERROR: ${error}`)
    console.error(`FAILED: ${result.errors.length} release-blocking issue(s)`)
    process.exitCode = 1
    return
  }
  console.log(`OK: ${result.incidentCount} incident files pass schema, cross-record, research, and dist checks`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main()
