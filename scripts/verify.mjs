/**
 * Re-derives a protocol file's incident measurements from onchain sources.
 *
 * For every incident with an exploitTx and victimContract:
 *   - incident timestamp = the attack transaction's block timestamp
 *   - deployment timestamp = victim creation tx (Etherscan v2 lookup)
 *   - last pre-incident change = max(deployment, EIP-1967 Upgraded logs in
 *     [creation block, incident block])
 *   - code age = incident - last change
 * and compares the result to the stored `measurement`.
 *
 * Rows measured from a documented change (`documentedLastChange`) or without
 * an exploit tx are reported as MANUAL — their evidence is the cited source,
 * not a standard event, and cannot be re-derived mechanically.
 *
 * Usage:
 *   ETHERSCAN_API_KEY=... RPC_URL_ETHEREUM=... node scripts/verify.mjs protocols/euler-finance.json
 *   (set RPC_URL_<CHAIN> for each chain you want to verify; needs archive access for logs)
 */
import { readFileSync } from 'node:fs'

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

async function rpc(chain, method, params) {
  const url = process.env[`RPC_URL_${chain.toUpperCase()}`]
  if (!url) throw new Error(`set RPC_URL_${chain.toUpperCase()}`)
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const body = await res.json()
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`)
  return body.result
}

async function etherscan(chain, params) {
  const qs = new URLSearchParams({
    chainid: String(CHAIN_IDS[chain]),
    ...params,
    apikey: process.env.ETHERSCAN_API_KEY ?? '',
  })
  const res = await fetch(`https://api.etherscan.io/v2/api?${qs}`)
  const body = await res.json()
  if (body.status !== '1') throw new Error(`etherscan: ${body.message}`)
  return body.result
}

const blockTs = async (chain, tag) =>
  Number.parseInt((await rpc(chain, 'eth_getBlockByNumber', [tag, false])).timestamp, 16)

async function verify(incident) {
  const { chain, victimContract, exploitTx, measurement } = incident
  if (!exploitTx || !victimContract || measurement?.status !== 'OK') return 'SKIP (not mechanically measured)'
  if (incident.documentedLastChange) return 'MANUAL (documented change; check the cited source)'
  const tx = await rpc(chain, 'eth_getTransactionByHash', [exploitTx])
  if (!tx?.blockNumber) return 'FAIL: exploit tx not found'
  const incidentTs = await blockTs(chain, tx.blockNumber)
  const creation = (
    await etherscan(chain, {
      module: 'contract',
      action: 'getcontractcreation',
      contractaddresses: victimContract,
    })
  )[0]
  if (!creation) return 'FAIL: no creation info'
  let deployTs
  let creationBlock = '0x0'
  if (creation.timestamp) deployTs = Number(creation.timestamp)
  else {
    const ctx = await rpc(chain, 'eth_getTransactionByHash', [creation.txHash])
    creationBlock = ctx.blockNumber
    deployTs = await blockTs(chain, ctx.blockNumber)
  }
  const logs = await rpc(chain, 'eth_getLogs', [
    { address: victimContract, topics: [UPGRADED_TOPIC], fromBlock: creationBlock, toBlock: tx.blockNumber },
  ]).catch(() => [])
  let lastChange = deployTs
  for (const log of logs) {
    const ts = await blockTs(chain, log.blockNumber)
    if (ts <= incidentTs && ts > lastChange) lastChange = ts
  }
  const age = incidentTs - lastChange
  const stored = measurement.codeAgeSeconds
  const drift = Math.abs(age - stored)
  return drift <= 1
    ? `OK (age ${age}s matches stored ${stored}s)`
    : `MISMATCH: derived ${age}s vs stored ${stored}s`
}

const file = process.argv[2]
if (!file) {
  console.error('usage: node scripts/verify.mjs protocols/<slug>.json')
  process.exit(1)
}
const doc = JSON.parse(readFileSync(file, 'utf-8'))
for (const incident of doc.incidents) {
  try {
    console.log(`${incident.name} (${incident.chain}): ${await verify(incident)}`)
  } catch (e) {
    console.log(`${incident.name} (${incident.chain}): ERROR ${e.message}`)
  }
}
