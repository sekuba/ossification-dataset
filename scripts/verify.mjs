/**
 * Re-derives a protocol file's incident measurements from onchain sources.
 *
 * For every incident with an exploitTx and victimContract:
 *   - incident timestamp = the attack transaction's block timestamp
 *   - deployment timestamp = victim creation tx (Etherscan v2 lookup, falling
 *     back to a binary search over eth_getCode when the chain has no explorer)
 *   - last pre-incident change = max(deployment, EIP-1967 Upgraded logs in
 *     [creation block, incident block]) EXCLUDING attacker-caused events: a
 *     log emitted by the exploit tx itself, or by a tx sent from the recorded
 *     attacker, is part of the attack, not a code change by the protocol
 *   - code age = incident - last change
 * and compares every stored measurement field to the derivation. Also checks
 * inclusion rule 2: the victim's creator must be neither the attacker nor the
 * exploit-tx sender.
 *
 * Rows measured from a documented change (`documentedLastChange`) are reported
 * as MANUAL - their evidence is the cited source, not a standard event, and
 * cannot be re-derived mechanically.
 *
 * A failed upgrade-log lookup reports UNVERIFIED rather than being treated as
 * "no upgrades": swallowing it would silently derive the deployment age and
 * confirm a row measured from the wrong basis.
 *
 * Usage:
 *   node scripts/verify.mjs protocols/euler-finance.json
 *   node scripts/verify.mjs --all          # sweep every mechanical row
 *   node scripts/verify.mjs --all --quiet  # only rows needing attention
 *
 * Env: ETHERSCAN_API_KEY is enough for every chain Etherscan v2 serves - the
 * lookups fall back to its JSON-RPC proxy and logs module. Set
 * RPC_URL_<CHAIN> or <CHAIN>_RPC_URL (archive access) to use your own
 * endpoint instead, which is faster and required for chains Etherscan does
 * not serve. Rows on a chain with neither are reported NO-RPC, never OK.
 */
import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const UPGRADED_TOPIC =
  '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b'
const CHAIN_IDS = {
  ethereum: 1,
  optimism: 10,
  bsc: 56,
  gnosis: 100,
  polygon: 137,
  base: 8453,
  arbitrum: 42161,
  avalanche: 43114,
  linea: 59144,
  blast: 81457,
  scroll: 534352,
  celo: 42220,
  mantle: 5000,
  mode: 34443,
}
// Chains absent here (or absent from Etherscan v2) still work: the creation
// lookup falls back to RPC. Any chain is measurable given an RPC url.

const rpcUrl = (chain) =>
  process.env[`RPC_URL_${chain.toUpperCase()}`] ?? process.env[`${chain.toUpperCase()}_RPC_URL`]

/**
 * fetch + JSON parse, retrying transport-level flakiness (5xx, truncated or
 * non-JSON bodies, dropped connections). A sweep over hundreds of rows hits
 * these regularly, and a retried hiccup must not be reported as a data problem.
 */
async function fetchJson(url, init, attempts = 5) {
  let lastError
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, init)
      if (res.status >= 500 || res.status === 429) throw new Error(`HTTP ${res.status}`)
      return await res.json()
    } catch (e) {
      lastError = e
      await new Promise((r) => setTimeout(r, 400 * 2 ** i))
    }
  }
  throw lastError
}

/** Methods Etherscan v2 serves through its JSON-RPC proxy module. */
const PROXY_METHODS = new Set([
  'eth_getTransactionByHash',
  'eth_getBlockByNumber',
  'eth_getCode',
  'eth_getStorageAt',
  'eth_getTransactionReceipt',
])

async function rpc(chain, method, params) {
  const url = rpcUrl(chain)
  if (!url) {
    // No endpoint configured: fall back to the Etherscan v2 proxy so a row can
    // be re-derived with an API key alone, on any chain Etherscan serves.
    if (!CHAIN_IDS[chain] || !PROXY_METHODS.has(method))
      throw new Error(`set RPC_URL_${chain.toUpperCase()} or ${chain.toUpperCase()}_RPC_URL`)
    return etherscanProxy(chain, method, params)
  }
  const body = await fetchJson(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`)
  return body.result
}

async function etherscan(chain, params) {
  const qs = new URLSearchParams({
    chainid: String(CHAIN_IDS[chain]),
    ...params,
    apikey: process.env.ETHERSCAN_API_KEY ?? '',
  })
  const body = await etherscanFetch(qs)
  if (body.status !== '1') throw new Error(`etherscan: ${body.message}`)
  return body.result
}

/**
 * Etherscan v2's JSON-RPC proxy, used for chains with no configured endpoint.
 * Proxy responses carry the JSON-RPC envelope rather than Etherscan's own
 * status/message wrapper.
 */
async function etherscanProxy(chain, method, params) {
  const qs = new URLSearchParams({
    chainid: String(CHAIN_IDS[chain]),
    module: 'proxy',
    action: method,
    apikey: process.env.ETHERSCAN_API_KEY ?? '',
  })
  if (method === 'eth_getTransactionByHash' || method === 'eth_getTransactionReceipt') qs.set('txhash', params[0])
  if (method === 'eth_getBlockByNumber') {
    qs.set('tag', params[0])
    qs.set('boolean', String(params[1] ?? false))
  }
  if (method === 'eth_getCode' || method === 'eth_getStorageAt') {
    qs.set('address', params[0])
    if (method === 'eth_getStorageAt') qs.set('position', params[1])
    qs.set('tag', params[method === 'eth_getStorageAt' ? 2 : 1])
  }
  const body = await etherscanFetch(qs)
  if (body.error) throw new Error(`${method} (etherscan proxy): ${JSON.stringify(body.error)}`)
  return body.result
}

/**
 * One Etherscan v2 request, retrying its transient failures. Etherscan signals
 * throttling and server-side hiccups with status "0" and a plain-string result
 * rather than an HTTP error, which would otherwise surface as a bogus "missing
 * block" or an UNVERIFIED row downstream.
 */
async function etherscanFetch(qs, attempts = 6) {
  for (let i = 0; ; i++) {
    const body = await fetchJson(`https://api.etherscan.io/v2/api?${qs}`)
    const transient =
      typeof body.result === 'string' &&
      /rate limit|too many|timeout|server too busy|unexpected error/i.test(body.result)
    if (!transient || i >= attempts - 1) return body
    await new Promise((r) => setTimeout(r, 400 * 2 ** i))
  }
}

/**
 * EIP-1967 Upgraded logs through Etherscan's logs module, for chains with no
 * configured endpoint. Etherscan returns each log's timeStamp directly, so the
 * caller needs no extra block lookups.
 */
async function etherscanLogs(chain, address, fromBlock, toBlock) {
  const out = []
  for (let page = 1; page <= 10; page++) {
    const qs = new URLSearchParams({
      chainid: String(CHAIN_IDS[chain]),
      module: 'logs',
      action: 'getLogs',
      address,
      topic0: UPGRADED_TOPIC,
      fromBlock: String(Number.parseInt(fromBlock, 16)),
      toBlock: String(Number.parseInt(toBlock, 16)),
      page: String(page),
      offset: '1000',
      apikey: process.env.ETHERSCAN_API_KEY ?? '',
    })
    const body = await etherscanFetch(qs)
    // "No records found" is a valid empty result, not a failed lookup.
    if (body.status !== '1') {
      if (/no records found/i.test(body.message ?? '')) break
      throw new Error(`etherscan logs: ${body.message} ${JSON.stringify(body.result ?? '')}`)
    }
    out.push(...body.result)
    if (body.result.length < 1000) break
  }
  return out
}

/**
 * Block timestamp by number, falling back to the block hash: some endpoints
 * (rpc.linea.build among them) answer eth_getBlockByNumber with null for older
 * blocks they will happily serve by hash. Logs and txs both carry blockHash.
 */
const blockTs = async (chain, tag, hash) => {
  const byNumber = await rpc(chain, 'eth_getBlockByNumber', [tag, false])
  if (byNumber?.timestamp) return Number.parseInt(byNumber.timestamp, 16)
  if (hash) {
    const byHash = await rpc(chain, 'eth_getBlockByHash', [hash, false])
    if (byHash?.timestamp) return Number.parseInt(byHash.timestamp, 16)
  }
  throw new Error(`block ${tag} not served by this endpoint`)
}

/**
 * Creation block over plain RPC: binary-search the first block at which the
 * address has code. Needed for chains Etherscan v2 does not serve.
 */
async function creationBlockViaRpc(chain, address, headBlock) {
  const hasCode = async (b) =>
    (await rpc(chain, 'eth_getCode', [address, '0x' + b.toString(16)])) !== '0x'
  if (!(await hasCode(headBlock).catch(() => false))) return null
  let lo = 0
  let hi = headBlock
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2)
    if (await hasCode(mid)) hi = mid
    else lo = mid + 1
  }
  return lo
}

/**
 * eth_getLogs over [from, to], halving the window whenever a provider rejects
 * the range. A range cap is a provider quirk, not a failure to verify - only
 * a genuinely broken lookup should reach the UNVERIFIED path.
 */
/**
 * Per-chain block-range limit, learned the first time a provider rejects a
 * window and then reused. Without this, every sub-range rediscovers the limit
 * by halving from the top, which on a wide range (a chain with no explorer, so
 * the search starts at the victim's creation block millions of blocks back)
 * costs thousands of requests instead of hundreds.
 */
const rangeLimit = new Map()

async function getLogsChunked(chain, address, fromBlock, toBlock) {
  if (!rpcUrl(chain)) return etherscanLogs(chain, address, fromBlock, toBlock)
  const out = []
  const query = (lo, hi) =>
    rpc(chain, 'eth_getLogs', [
      {
        address,
        topics: [UPGRADED_TOPIC],
        fromBlock: '0x' + lo.toString(16),
        toBlock: '0x' + hi.toString(16),
      },
    ])

  const from = Number.parseInt(fromBlock, 16)
  const to = Number.parseInt(toBlock, 16)

  // Learn the provider's window size on one probe at the start of the range,
  // halving until a request succeeds, before fanning out over the rest.
  let cursor = from
  while (cursor <= to) {
    const limit = rangeLimit.get(chain) ?? to - from + 1
    const hi = Math.min(cursor + limit - 1, to)
    try {
      out.push(...(await query(cursor, hi)))
      cursor = hi + 1
      break
    } catch (e) {
      const span = hi - cursor + 1
      // A single block that still fails is a real error, not a range cap.
      if (span <= 1) throw e
      rangeLimit.set(chain, Math.max(1, Math.floor(span / 2)))
    }
  }

  // Remaining windows are independent: run them with bounded concurrency, or a
  // chain with a small cap and a long history takes thousands of serial round
  // trips (Fantom's 10k-block cap over a multi-million-block history).
  const windows = []
  const limit = rangeLimit.get(chain) ?? to - from + 1
  for (let lo = cursor; lo <= to; lo += limit) windows.push([lo, Math.min(lo + limit - 1, to)])

  const CONCURRENCY = 8
  for (let i = 0; i < windows.length; i += CONCURRENCY) {
    const batch = windows.slice(i, i + CONCURRENCY)
    const parts = await Promise.all(batch.map(([lo, hi]) => query(lo, hi)))
    for (const part of parts) out.push(...part)
  }
  return out
}

async function verify(incident) {
  const { chain, victimContract, exploitTx, attacker, measurement } = incident
  if (!exploitTx || !victimContract || measurement?.status !== 'OK') return 'SKIP (not mechanically measured)'
  if (incident.documentedLastChange) return 'MANUAL (documented change; check the cited source)'
  // Verifiable with an endpoint, or with an API key alone on a chain Etherscan serves.
  if (!rpcUrl(chain) && !CHAIN_IDS[chain]) return `NO-RPC (${chain})`
  const tx = await rpc(chain, 'eth_getTransactionByHash', [exploitTx])
  if (!tx?.blockNumber) return 'FAIL: exploit tx not found'
  const incidentTs = await blockTs(chain, tx.blockNumber, tx.blockHash)
  const attackerAddrs = new Set(
    [attacker, tx.from].filter(Boolean).map((a) => a.toLowerCase()),
  )
  const creation = await etherscan(chain, {
    module: 'contract',
    action: 'getcontractcreation',
    contractaddresses: victimContract,
  })
    .then((r) => r[0])
    .catch(() => null)
  let deployTs
  let creationBlock = '0x0'
  if (creation?.contractCreator && attackerAddrs.has(creation.contractCreator.toLowerCase()))
    return `FAIL: victim creator ${creation.contractCreator} is the attacker/exploit-tx sender (inclusion rule 2)`
  if (creation?.timestamp) {
    deployTs = Number(creation.timestamp)
    if (creation.blockNumber) creationBlock = '0x' + Number(creation.blockNumber).toString(16)
  } else if (creation?.txHash) {
    const ctx = await rpc(chain, 'eth_getTransactionByHash', [creation.txHash])
    creationBlock = ctx.blockNumber
    deployTs = await blockTs(chain, ctx.blockNumber, ctx.blockHash)
  } else {
    // No explorer for this chain - binary-search eth_getCode over plain RPC.
    const block = await creationBlockViaRpc(chain, victimContract, Number.parseInt(tx.blockNumber, 16))
    if (block === null) return 'FAIL: no creation info (explorer and RPC lookup both failed)'
    creationBlock = '0x' + block.toString(16)
    deployTs = await blockTs(chain, creationBlock)
  }
  let logs
  try {
    logs = await getLogsChunked(chain, victimContract, creationBlock, tx.blockNumber)
  } catch (e) {
    // Never treat a failed lookup as "no upgrades": that silently yields the
    // deployment age and would confirm a row that measured from the wrong basis.
    return `UNVERIFIED: upgrade-log lookup failed (${e.message}); cannot confirm the last change`
  }
  let lastChange = deployTs
  let eventCount = 0
  const excluded = []
  for (const log of logs) {
    // Etherscan's logs module returns timeStamp per log; plain RPC needs a lookup.
    const ts = log.timeStamp
      ? Number.parseInt(log.timeStamp, 16)
      : await blockTs(chain, log.blockNumber, log.blockHash)
    if (ts > incidentTs) continue
    // Attacker-caused events are part of the exploit, not a protocol change.
    if (log.transactionHash.toLowerCase() === exploitTx) {
      excluded.push('event in the exploit tx itself')
      continue
    }
    const logTx = await rpc(chain, 'eth_getTransactionByHash', [log.transactionHash])
    if (logTx?.from && attackerAddrs.has(logTx.from.toLowerCase())) {
      excluded.push(`event in attacker tx ${log.transactionHash.slice(0, 10)}`)
      continue
    }
    eventCount++
    if (ts > lastChange) lastChange = ts
  }
  const age = incidentTs - lastChange
  const m = measurement
  const diffs = []
  if (Math.abs(age - m.codeAgeSeconds) > 1) diffs.push(`age ${age} vs ${m.codeAgeSeconds}`)
  if (Math.abs(incidentTs - m.incidentTimestamp) > 1) diffs.push(`incident ${incidentTs} vs ${m.incidentTimestamp}`)
  if (Math.abs(deployTs - m.deployTimestamp) > 1) diffs.push(`deploy ${deployTs} vs ${m.deployTimestamp}`)
  if (Math.abs(lastChange - m.lastChangeTimestamp) > 1) diffs.push(`lastChange ${lastChange} vs ${m.lastChangeTimestamp}`)
  if (eventCount !== m.upgradeEventCount) diffs.push(`events ${eventCount} vs ${m.upgradeEventCount}`)
  const note = excluded.length ? ` [excluded ${excluded.length} attacker-caused event(s): ${excluded.join('; ')}]` : ''
  return diffs.length ? `MISMATCH: ${diffs.join(', ')}${note}` : `OK (age ${age}s)${note}`
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const files = args.includes('--all')
  ? readdirSync(path.join(root, 'protocols')).sort().map((f) => path.join(root, 'protocols', f))
  : args.filter((a) => !a.startsWith('--'))
if (files.length === 0) {
  console.error('usage: node scripts/verify.mjs protocols/<slug>.json | --all')
  process.exit(1)
}

const tally = {}
let failures = 0
for (const file of files) {
  const doc = JSON.parse(readFileSync(file, 'utf-8'))
  for (const incident of doc.incidents) {
    let result
    try {
      result = await verify(incident)
    } catch (e) {
      result = `ERROR ${e.message}`
    }
    const kind = result.split(/[ :(]/)[0]
    tally[kind] = (tally[kind] ?? 0) + 1
    if (kind === 'MISMATCH' || kind === 'FAIL') failures++
    if (!args.includes('--all') || !['OK', 'SKIP', 'MANUAL', 'NO-RPC'].includes(kind) || !args.includes('--quiet'))
      console.log(`${path.basename(file)} ${incident.name} (${incident.chain}): ${result}`)
  }
}
if (args.includes('--all')) {
  console.log(`\nsummary: ${Object.entries(tally).map(([k, v]) => `${k}=${v}`).join(' ')}`)
  // Only MISMATCH/FAIL are data problems and fail the sweep. ERROR and
  // UNVERIFIED are provider-side and inconclusive - re-run those rows rather
  // than reading them as either confirmation or contradiction.
  const inconclusive = (tally.ERROR ?? 0) + (tally.UNVERIFIED ?? 0)
  if (inconclusive) console.log(`${inconclusive} row(s) inconclusive (provider error); re-run them individually`)
  process.exit(failures ? 1 : 0)
}
