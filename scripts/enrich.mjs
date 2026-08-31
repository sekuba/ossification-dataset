#!/usr/bin/env node

/**
 * Mechanically enrich declared incident anchors from RPC and explorer data.
 *
 * The script fills reproducible coordinates and hashes; it never changes
 * verification tiers or curve eligibility.
 *
 *   node scripts/enrich.mjs incidents/1/<tx>.json
 *   node scripts/enrich.mjs --all --write
 *   node scripts/enrich.mjs --all --write --explorer
 */
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { incidentToDisk, normalizeIncident } from './build.mjs'

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const EMPTY_CODE_HASH = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'

const RPC_ENV_BY_CHAIN_ID = {
  1: ['ETHEREUM_RPC_URL'],
  10: ['OPTIMISM_RPC_URL'],
  56: ['BSC_RPC_URL'],
  57: ['SYSCOIN_RPC_URL'],
  100: ['GNOSIS_RPC_URL'],
  137: ['POLYGONPOS_RPC_URL', 'POLYGON_RPC_URL'],
  250: ['FANTOM_RPC_URL'],
  295: ['HEDERA_RPC_URL'],
  324: ['ZKSYNC2_RPC_URL', 'ZKSYNC_RPC_URL'],
  5000: ['MANTLE_RPC_URL'],
  8453: ['BASE_RPC_URL'],
  42220: ['CELO_RPC_URL'],
  42161: ['ARBITRUM_RPC_URL'],
  43114: ['AVALANCHE_RPC_URL'],
  59144: ['LINEA_RPC_URL'],
  60808: ['BOB_RPC_URL', 'BOBANETWORK_RPC_URL'],
  81457: ['BLAST_RPC_URL'],
  534352: ['SCROLL_RPC_URL'],
}

const EXPLORER_KEY_ENV_BY_CHAIN_ID = {
  1: ['ETHERSCAN_API_KEY'],
  10: ['OPTIMISM_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  56: ['BSC_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  100: ['GNOSIS_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  137: ['POLYGONPOS_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  324: ['ZKSYNC2_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  5000: ['MANTLE_ETHERSCAN_V1_API_KEY', 'ETHERSCAN_API_KEY'],
  8453: ['BASE_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  42220: ['CELO_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  42161: ['ARBITRUM_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  43114: ['ETHERSCAN_API_KEY'],
  59144: ['LINEA_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  60808: ['BOBANETWORK_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  81457: ['BLAST_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
  534352: ['SCROLL_ETHERSCAN_API_KEY', 'ETHERSCAN_API_KEY'],
}

const lower = (value) => value?.toLowerCase()
const hexInt = (value) => (value === null || value === undefined ? null : Number.parseInt(value, 16))

function configured(names) {
  return names.find((name) => process.env[name]) ? process.env[names.find((name) => process.env[name])] : undefined
}

function rpcUrl(chainId) {
  return configured(RPC_ENV_BY_CHAIN_ID[chainId] ?? [])
}

async function fetchJson(url, init, attempts = 5) {
  let lastError
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetch(url, init)
      if (response.status === 429 || response.status >= 500)
        throw new Error(`HTTP ${response.status}`)
      const value = await response.json()
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return value
    } catch (error) {
      lastError = error
      if (attempt + 1 < attempts)
        await new Promise((resolve) => setTimeout(resolve, 300 * 2 ** attempt))
    }
  }
  throw lastError
}

async function rpc(chainId, method, params) {
  const url = rpcUrl(chainId)
  if (!url) throw new Error(`no RPC configured for eip155:${chainId}`)
  const body = await fetchJson(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (body.error) throw new Error(`${method}: ${body.error.message ?? JSON.stringify(body.error)}`)
  return body.result
}

function walkJsonFiles(directory) {
  if (!existsSync(directory)) return []
  return readdirSync(directory).sort().flatMap((entry) => {
    const absolute = path.join(directory, entry)
    if (statSync(absolute).isDirectory()) return walkJsonFiles(absolute)
    return entry.endsWith('.json') ? [absolute] : []
  })
}

function collectFrames(frame, ancestors = [], result = []) {
  if (!frame || typeof frame !== 'object') return result
  result.push({ frame, ancestors })
  for (const child of frame.calls ?? []) collectFrames(child, [...ancestors, frame], result)
  return result
}

async function transactionAnchor(chainId, transactionHash) {
  const [tx, receipt] = await Promise.all([
    rpc(chainId, 'eth_getTransactionByHash', [transactionHash]),
    rpc(chainId, 'eth_getTransactionReceipt', [transactionHash]),
  ])
  if (!tx || !receipt) throw new Error(`transaction ${transactionHash} is unavailable`)
  if (receipt.status !== undefined && receipt.status !== '0x1')
    throw new Error(`transaction ${transactionHash} has status ${receipt.status}`)
  let block = await rpc(chainId, 'eth_getBlockByNumber', [tx.blockNumber, false])
  if (!block && receipt.blockHash)
    block = await rpc(chainId, 'eth_getBlockByHash', [receipt.blockHash, false])
  if (!block) throw new Error(`block ${tx.blockNumber} is unavailable`)
  return {
    blockNumber: hexInt(tx.blockNumber),
    transactionIndex: hexInt(tx.transactionIndex),
    timestamp: hexInt(block.timestamp),
    tx,
    receipt,
  }
}

function applyPosition(anchor, value) {
  let changed = false
  for (const key of ['blockNumber', 'transactionIndex', 'timestamp']) {
    if (anchor[key] !== value[key]) {
      anchor[key] = value[key]
      changed = true
    }
  }
  return changed
}

function removeLimitation(verification, text) {
  const index = verification.limitations.indexOf(text)
  if (index === -1) return false
  verification.limitations.splice(index, 1)
  return true
}

function nextSourceId(incident) {
  const highest = incident.sources.reduce((result, source) => {
    const value = Number(/^source-([1-9][0-9]*)$/.exec(source.id)?.[1] ?? 0)
    return Math.max(result, value)
  }, 0)
  return `source-${highest + 1}`
}

function ensureOnchainSource(incident, target, transactionHash, claims) {
  const chainId = incident.incident.chainId
  let source = incident.sources.find(
    (candidate) =>
      candidate.type === 'onchain-transaction' &&
      candidate.chainId === chainId &&
      candidate.transactionHash === transactionHash,
  )
  let changed = false
  if (!source) {
    source = {
      id: nextSourceId(incident),
      type: 'onchain-transaction',
      chainId,
      transactionHash,
    }
    incident.sources.push(source)
    changed = true
  }
  if (target && claims.includes('age-history') && !target.evidence.ageSourceIds.includes(source.id)) {
    target.evidence.ageSourceIds.push(source.id)
    target.evidence.ageSourceIds.sort()
    changed = true
  }
  if (target && claims.includes('target-identity') && !target.evidence.identitySourceIds.includes(source.id)) {
    target.evidence.identitySourceIds.push(source.id)
    target.evidence.identitySourceIds.sort()
    changed = true
  }
  return changed
}

async function explorerCreation(chainId, address) {
  const apiKey = configured(EXPLORER_KEY_ENV_BY_CHAIN_ID[chainId] ?? [])
  if (!apiKey) return null
  const url = new URL('https://api.etherscan.io/v2/api')
  url.searchParams.set('chainid', String(chainId))
  url.searchParams.set('module', 'contract')
  url.searchParams.set('action', 'getcontractcreation')
  url.searchParams.set('contractaddresses', address)
  url.searchParams.set('apikey', apiKey)
  const body = await fetchJson(url)
  if (body.status !== '1' || !Array.isArray(body.result) || body.result.length !== 1) return null
  const result = body.result[0]
  if (!/^0x[0-9a-fA-F]{64}$/.test(result.txHash ?? '')) return null
  return {
    transactionHash: lower(result.txHash),
    creatorAddress: /^0x[0-9a-fA-F]{40}$/.test(result.contractCreator ?? '')
      ? lower(result.contractCreator)
      : null,
  }
}

async function creationFromTrace(chainId, transactionHash, executionAddress) {
  try {
    const trace = await rpc(chainId, 'debug_traceTransaction', [
      transactionHash,
      { tracer: 'callTracer', tracerConfig: { onlyTopCall: false, withLog: false } },
    ])
    const creation = collectFrames(trace).find(
      ({ frame }) =>
        ['CREATE', 'CREATE2'].includes(String(frame.type).toUpperCase()) &&
        lower(frame.to) === executionAddress,
    )?.frame
    return creation?.from ? lower(creation.from) : null
  } catch {
    return null
  }
}

function delegatedArtifact(trace, executionAddress) {
  const candidates = collectFrames(trace)
    .filter(
      ({ frame, ancestors }) =>
        String(frame.type).toUpperCase() === 'DELEGATECALL' &&
        lower(ancestors.at(-1)?.to) === executionAddress,
    )
    .map(({ frame }) => lower(frame.to))
    .filter(Boolean)
  const unique = [...new Set(candidates)]
  return unique.length === 1 ? unique[0] : null
}

async function prestateCodeHash(chainId, transactionHash, address) {
  try {
    const prestate = await rpc(chainId, 'debug_traceTransaction', [
      transactionHash,
      { tracer: 'prestateTracer', tracerConfig: { diffMode: false } },
    ])
    const key = Object.keys(prestate ?? {}).find((candidate) => lower(candidate) === address)
    const code = prestate?.[key]?.code
    if (!code || code === '0x') return null
    const hash = lower(await rpc(chainId, 'web3_sha3', [code]))
    return hash === EMPTY_CODE_HASH ? null : hash
  } catch {
    return null
  }
}

async function enrichFile(file, useExplorer) {
  const original = readFileSync(file, 'utf8')
  const incident = normalizeIncident(JSON.parse(original))
  const chainId = incident.incident.chainId
  const exploitHash = incident.incident.exploit.transactionHash
  const changes = []

  const exploit = await transactionAnchor(chainId, exploitHash)
  if (applyPosition(incident.incident.exploit, exploit)) changes.push('exploit-anchor')
  if (ensureOnchainSource(incident, null, exploitHash, ['incident-anchor'])) changes.push('exploit-source')
  if (
    removeLimitation(
      incident.verification,
      'The exploit block or transaction index remains unresolved.',
    )
  ) changes.push('exploit-limitation')

  let callTrace
  const needsCallTrace = incident.targets.some(
    (target) =>
      target.codeArtifact.address === null &&
      target.relationship !== 'unknown' &&
      target.relationship !== 'direct',
  )
  let prestate
  if (needsCallTrace) {
    try {
      callTrace = await rpc(chainId, 'debug_traceTransaction', [
        exploitHash,
        { tracer: 'callTracer', tracerConfig: { onlyTopCall: false, withLog: false } },
      ])
    } catch {
      callTrace = null
    }
  }

  for (const target of incident.targets) {
    if (target.relationship === 'direct' && target.codeArtifact.address === null) {
      target.codeArtifact.address = target.executionAddress
      changes.push(`${target.id}:direct-artifact`)
    }
    if (
      target.codeArtifact.address === null &&
      target.relationship !== 'unknown' &&
      target.relationship !== 'direct' &&
      callTrace
    ) {
      const artifact = delegatedArtifact(callTrace, target.executionAddress)
      if (artifact) {
        target.codeArtifact.address = artifact
        changes.push(`${target.id}:traced-artifact`)
      }
    }
    if (target.codeArtifact.address && target.codeArtifact.codeHash === null) {
      if (prestate === undefined) {
        prestate = await rpc(chainId, 'debug_traceTransaction', [
          exploitHash,
          { tracer: 'prestateTracer', tracerConfig: { diffMode: false } },
        ]).catch(() => null)
      }
      let hash = null
      if (prestate) {
        const key = Object.keys(prestate).find(
          (candidate) => lower(candidate) === target.codeArtifact.address,
        )
        const code = prestate?.[key]?.code
        if (code && code !== '0x')
          hash = lower(await rpc(chainId, 'web3_sha3', [code]).catch(() => null))
      }
      if (!hash) hash = await prestateCodeHash(chainId, exploitHash, target.codeArtifact.address)
      if (hash && hash !== EMPTY_CODE_HASH) {
        target.codeArtifact.codeHash = hash
        changes.push(`${target.id}:code-hash`)
      }
    }

    const deployment = target.deployment
    if (deployment.kind !== 'system-genesis' && !deployment.transactionHash && useExplorer) {
      const discovered = await explorerCreation(chainId, target.executionAddress)
      if (discovered) {
        deployment.transactionHash = discovered.transactionHash
        if (!deployment.creatorAddress && discovered.creatorAddress)
          deployment.creatorAddress = discovered.creatorAddress
        changes.push(`${target.id}:deployment-discovery`)
      }
    }
    if (deployment.transactionHash) {
      const anchor = await transactionAnchor(chainId, deployment.transactionHash)
      if (applyPosition(deployment, anchor)) changes.push(`${target.id}:deployment-anchor`)
      const receiptAddress = lower(anchor.receipt.contractAddress)
      const creator = receiptAddress === target.executionAddress
        ? lower(anchor.tx.from)
        : await creationFromTrace(chainId, deployment.transactionHash, target.executionAddress)
      if (creator && deployment.creatorAddress !== creator) {
        deployment.creatorAddress = creator
        changes.push(`${target.id}:creator`)
      }
      if (
        target.ageReset.kind === 'deployment' &&
        target.ageReset.mechanism.type === 'deployment'
      ) {
        for (const key of ['timestamp', 'blockNumber', 'transactionHash', 'transactionIndex']) {
          if (target.ageReset[key] !== deployment[key]) {
            target.ageReset[key] = deployment[key]
            changes.push(`${target.id}:deployment-reset`)
          }
        }
      }
      if (
        ensureOnchainSource(
          incident,
          target,
          deployment.transactionHash,
          ['target-identity', 'age-history'],
        )
      ) changes.push(`${target.id}:deployment-source`)
    }

    const reset = target.ageReset
    if (reset.transactionHash && reset.transactionHash !== deployment.transactionHash) {
      const anchor = await transactionAnchor(chainId, reset.transactionHash)
      if (applyPosition(reset, anchor)) changes.push(`${target.id}:age-reset-anchor`)
      if (
        ensureOnchainSource(
          incident,
          target,
          reset.transactionHash,
          reset.kind === 'configuration-change'
            ? ['age-history']
            : ['target-identity', 'age-history'],
        )
      ) changes.push(`${target.id}:age-reset-source`)
    }
    const age = incident.incident.exploit.timestamp - reset.timestamp
    if (target.codeAgeSeconds !== age) {
      target.codeAgeSeconds = age
      changes.push(`${target.id}:age`)
    }
    if (
      target.codeArtifact.address &&
      target.codeArtifact.codeHash &&
      removeLimitation(
        target.verification,
        'The executing code artifact and its code hash have not been established in structured evidence.',
      )
    ) changes.push(`${target.id}:artifact-limitation`)
    const completeAnchors = deployment.kind === 'system-genesis'
      ? reset.kind === 'deployment'
        ? [deployment.blockNumber, reset.blockNumber]
        : [deployment.blockNumber, reset.blockNumber, reset.transactionHash, reset.transactionIndex]
      : [
        deployment.blockNumber,
        deployment.transactionHash,
        deployment.transactionIndex,
        deployment.creatorAddress,
        reset.blockNumber,
        reset.transactionHash,
        reset.transactionIndex,
      ]
    if (
      completeAnchors.every((value) => value !== null) &&
      removeLimitation(
        target.verification,
        'One or more target block, transaction, ordering, or creator anchors remain unresolved.',
      )
    ) changes.push(`${target.id}:anchor-limitation`)
  }

  const serialized = `${JSON.stringify(incidentToDisk(incident), null, 2)}\n`
  return { incident, serialized, changed: serialized !== original, changes: [...new Set(changes)] }
}

async function mapLimit(values, limit, callback) {
  const results = new Array(values.length)
  let cursor = 0
  async function worker() {
    while (cursor < values.length) {
      const index = cursor++
      results[index] = await callback(values[index], index)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, worker))
  return results
}

const args = process.argv.slice(2)
const all = args.includes('--all')
const write = args.includes('--write')
const useExplorer = args.includes('--explorer')
const quiet = args.includes('--quiet')
const concurrencyArg = args.find((arg) => arg.startsWith('--concurrency='))
const concurrency = Number(concurrencyArg?.split('=')[1] ?? (useExplorer ? 2 : 4))
const files = all
  ? walkJsonFiles(path.join(ROOT, 'incidents'))
  : args
      .filter((arg) => !arg.startsWith('--'))
      .map((arg) => path.resolve(arg))

if (files.length === 0 || !Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
  console.error(
    'usage: node scripts/enrich.mjs <incident.json> | --all [--write] [--explorer] [--quiet] [--concurrency=N]',
  )
  process.exit(1)
}

let changed = 0
let failed = 0
const results = await mapLimit(files, concurrency, async (file) => {
  try {
    const result = await enrichFile(file, useExplorer)
    if (result.changed) {
      changed++
      if (write) writeFileSync(file, result.serialized)
      if (!quiet)
        console.log(
          `${write ? 'UPDATED' : 'WOULD_UPDATE'} ${path.relative(ROOT, file)}: ${result.changes.join(', ')}`,
        )
    }
    return result
  } catch (error) {
    failed++
    console.error(`FAILED ${path.relative(ROOT, file)}: ${error.message}`)
    return null
  }
})

const unchanged = results.filter((result) => result && !result.changed).length
console.log(
  `summary: files=${files.length} changed=${changed} unchanged=${unchanged} failed=${failed} mode=${write ? 'write' : 'dry-run'}`,
)
if (failed > 0) process.exitCode = 1
