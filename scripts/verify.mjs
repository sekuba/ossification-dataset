/**
 * Fail-closed onchain verifier for v2 incident records.
 *
 * This script checks stored anchors and machine-verifiable mechanism evidence.
 * It does not promote records or pretend to review root-cause/loss semantics.
 * Unsupported RPC methods and missing anchors are INCONCLUSIVE/INCOMPLETE.
 *
 *   node scripts/verify.mjs incidents/1/<tx>.json
 *   node scripts/verify.mjs --all
 *   node scripts/verify.mjs --all --quiet
 *   node scripts/verify.mjs incidents/1/<tx>.json --json
 *
 * Any FAIL, INCOMPLETE, or INCONCLUSIVE result exits nonzero. Use
 * --allow-incomplete only for exploratory bulk research. A successful result
 * is PASS_ANCHORS: the declared anchors reproduced, not a semantic review or
 * proof that the declared reset was the latest relevant code or state change.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

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

function rpcUrl(chainId) {
  for (const name of RPC_ENV_BY_CHAIN_ID[chainId] ?? []) {
    if (process.env[name]) return process.env[name]
  }
}

async function fetchJson(url, init, attempts = 5) {
  let lastError
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetch(url, init)
      if (response.status === 429 || response.status >= 500)
        throw new Error(`HTTP ${response.status}`)
      return await response.json()
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
  if (!url) {
    const expected = (RPC_ENV_BY_CHAIN_ID[chainId] ?? [`RPC_URL_FOR_CHAIN_${chainId}`]).join(' or ')
    throw new Error(`no RPC configured for eip155:${chainId}; set ${expected}`)
  }
  const body = await fetchJson(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (body.error) throw new Error(`${method}: ${body.error.message ?? JSON.stringify(body.error)}`)
  return body.result
}

const hexInt = (value) => (value === null || value === undefined ? null : Number.parseInt(value, 16))
const blockTag = (number) => `0x${number.toString(16)}`
const lower = (value) => value?.toLowerCase()
const storageWord = (value) => `0x${(value ?? '0x0').replace(/^0x/, '').padStart(64, '0')}`.toLowerCase()

function keyedCaseInsensitive(object, key) {
  if (!object || typeof object !== 'object') return undefined
  const actualKey = Object.keys(object).find((candidate) => lower(candidate) === lower(key))
  return actualKey === undefined ? undefined : object[actualKey]
}

function comparePosition(left, right) {
  return (
    left.blockNumber - right.blockNumber ||
    left.transactionIndex - right.transactionIndex ||
    (left.logIndex ?? -1) - (right.logIndex ?? -1)
  )
}

function walkIncidentFiles(directory) {
  if (!existsSync(directory)) return []
  const result = []
  for (const entry of readdirSync(directory).sort()) {
    const absolute = path.join(directory, entry)
    const stat = statSync(absolute)
    if (stat.isDirectory()) result.push(...walkIncidentFiles(absolute))
    else if (stat.isFile() && entry.endsWith('.json')) result.push(absolute)
  }
  return result
}

function collectTraceFrames(frame, ancestors = [], output = []) {
  if (!frame || typeof frame !== 'object') return output
  output.push({ frame, ancestors })
  for (const child of frame.calls ?? [])
    collectTraceFrames(child, [...ancestors, frame], output)
  return output
}

function createReport(file, incident) {
  return {
    file: path.relative(ROOT, file),
    incidentId: incident.id,
    tier: incident.verification?.tier,
    targetVerification: (incident.targets ?? []).map((target) => ({
      targetId: target.id,
      tier: target.verification?.tier,
      curveEligible: target.verification?.curveEligible,
    })),
    scope:
      'Reproduces declared anchors and mechanism evidence; semantic review and latest-change completeness remain separate claims.',
    checks: [],
  }
}

function pass(report, check, detail) {
  report.checks.push({ status: 'PASS', check, detail })
}

function incomplete(report, check, detail) {
  report.checks.push({ status: 'INCOMPLETE', check, detail })
}

function inconclusive(report, check, detail) {
  report.checks.push({ status: 'INCONCLUSIVE', check, detail })
}

function fail(report, check, detail) {
  report.checks.push({ status: 'FAIL', check, detail })
}

function eventCodeAddress(log, location) {
  const topicIndex = /^topic([1-3])-address$/.exec(location ?? '')?.[1]
  if (topicIndex) {
    const value = log.topics?.[Number(topicIndex)]
    return value?.length === 66 ? `0x${value.slice(-40)}`.toLowerCase() : null
  }
  const wordIndex = /^data-word-(0|[1-9][0-9]*)-address$/.exec(location ?? '')?.[1]
  if (wordIndex) {
    const data = log.data?.replace(/^0x/, '') ?? ''
    const word = data.slice(Number(wordIndex) * 64, Number(wordIndex) * 64 + 64)
    return word.length === 64 ? `0x${word.slice(-40)}`.toLowerCase() : null
  }
  return null
}

function createAddressInput(creatorAddress, nonce) {
  const addressItem = `94${creatorAddress.slice(2)}`
  let nonceItem
  if (nonce === 0) nonceItem = '80'
  else {
    let value = nonce.toString(16)
    if (value.length % 2 !== 0) value = `0${value}`
    const length = value.length / 2
    nonceItem = nonce < 128 ? value : `${(0x80 + length).toString(16)}${value}`
  }
  const payload = `${addressItem}${nonceItem}`
  const length = payload.length / 2
  if (length >= 56) throw new Error('CREATE proof RLP payload is too long')
  return `0x${(0xc0 + length).toString(16)}${payload}`
}

async function transactionAnchor(chainId, anchor, label, report, { requireSuccess = true } = {}) {
  if (anchor.blockNumber === null || anchor.transactionHash === null || anchor.transactionIndex === null) {
    incomplete(report, label, 'blockNumber, transactionHash, and transactionIndex are required')
    return null
  }
  const tx = await rpc(chainId, 'eth_getTransactionByHash', [anchor.transactionHash])
  if (!tx) {
    fail(report, label, `transaction ${anchor.transactionHash} not found`)
    return null
  }
  const receipt = await rpc(chainId, 'eth_getTransactionReceipt', [anchor.transactionHash])
  if (!receipt) {
    fail(report, label, `receipt ${anchor.transactionHash} not found`)
    return null
  }
  const actualBlock = hexInt(tx.blockNumber)
  const actualIndex = hexInt(tx.transactionIndex)
  let block = await rpc(chainId, 'eth_getBlockByNumber', [tx.blockNumber, false])
  if (!block && receipt.blockHash)
    block = await rpc(chainId, 'eth_getBlockByHash', [receipt.blockHash, false])
  if (!block) {
    inconclusive(report, label, `block ${actualBlock} is unavailable`)
    return null
  }
  const actualTimestamp = hexInt(block.timestamp)
  const diffs = []
  if (anchor.blockNumber !== actualBlock) diffs.push(`block ${anchor.blockNumber} != ${actualBlock}`)
  if (anchor.transactionIndex !== actualIndex)
    diffs.push(`transactionIndex ${anchor.transactionIndex} != ${actualIndex}`)
  if (anchor.timestamp !== actualTimestamp)
    diffs.push(`timestamp ${anchor.timestamp} != ${actualTimestamp}`)
  if (requireSuccess && receipt.status !== undefined && receipt.status !== '0x1')
    diffs.push(`receipt status is ${receipt.status}`)
  if (diffs.length > 0) fail(report, label, diffs.join(', '))
  else pass(report, label, `${anchor.transactionHash} at ${actualBlock}:${actualIndex}`)
  return { tx, receipt, block, blockNumber: actualBlock, transactionIndex: actualIndex, timestamp: actualTimestamp }
}

async function verifyTransactionSet(source, report) {
  const failures = []
  for (const transactionHash of source.transactionHashes) {
    const receipt = await rpc(source.chainId, 'eth_getTransactionReceipt', [transactionHash])
    if (!receipt) failures.push(`${transactionHash}: missing receipt`)
    else if (receipt.status !== undefined && receipt.status !== '0x1')
      failures.push(`${transactionHash}: receipt status ${receipt.status}`)
  }
  const label = `${source.id}:transaction-set`
  if (failures.length > 0) fail(report, label, failures.join(', '))
  else pass(report, label, `${source.transactionHashes.length} successful transactions on eip155:${source.chainId}`)
}

async function verifyTrace(chainId, exploitHash, target, report) {
  let trace
  try {
    trace = await rpc(chainId, 'debug_traceTransaction', [
      exploitHash,
      { tracer: 'callTracer', tracerConfig: { onlyTopCall: false, withLog: false } },
    ])
  } catch (error) {
    inconclusive(report, `${target.id}:execution-trace`, error.message)
    return
  }
  const entries = collectTraceFrames(trace)
  const executionEntries = entries.filter(
    ({ frame }) => lower(frame.to) === target.executionAddress,
  )
  if (executionEntries.length === 0) {
    fail(report, `${target.id}:execution-trace`, `executionAddress ${target.executionAddress} never executed`)
    return
  }
  pass(
    report,
    `${target.id}:execution-trace`,
    `executionAddress observed in ${entries.length} call frame(s)`,
  )

  if (target.codeArtifact.address) {
    const artifactEntries = entries.filter(
      ({ frame }) => lower(frame.to) === target.codeArtifact.address,
    )
    if (target.relationship === 'direct') {
      if (target.codeArtifact.address !== target.executionAddress)
        fail(
          report,
          `${target.id}:code-artifact-trace`,
          'direct target has different execution and artifact addresses',
        )
      else
        pass(
          report,
          `${target.id}:code-artifact-trace`,
          'direct runtime executed at the execution address',
        )
    } else if (target.relationship === 'unknown') {
      incomplete(
        report,
        `${target.id}:code-artifact-trace`,
        'unknown relationship cannot establish code-artifact causality',
      )
    } else {
      const related = artifactEntries.some(({ frame, ancestors }) => {
        const delegated = String(frame.type).toUpperCase() === 'DELEGATECALL'
        const belowExecution = ancestors.some(
          (ancestor) => lower(ancestor.to) === target.executionAddress,
        )
        return delegated && belowExecution
      })
      if (!related)
        fail(
          report,
          `${target.id}:code-artifact-trace`,
          `no DELEGATECALL from the execution context to ${target.codeArtifact.address}`,
        )
      else
        pass(
          report,
          `${target.id}:code-artifact-trace`,
          `declared ${target.relationship} relationship observed in call ancestry`,
        )
    }
  } else incomplete(report, `${target.id}:code-artifact-trace`, 'codeArtifact.address is null')
}

async function verifyCodeHash(chainId, target, exploitAnchor, report) {
  const address = target.codeArtifact.address
  const expected = target.codeArtifact.codeHash
  if (!address || !expected) {
    incomplete(report, `${target.id}:code-hash`, 'code artifact address/hash is incomplete')
    return
  }
  let actual
  let method
  try {
    const prestate = await rpc(chainId, 'debug_traceTransaction', [
      exploitAnchor.tx.hash,
      { tracer: 'prestateTracer', tracerConfig: { diffMode: false } },
    ])
    const matchingKey = Object.keys(prestate ?? {}).find((key) => lower(key) === address)
    const account = prestate?.[address] ?? prestate?.[matchingKey]
    if (account?.code) {
      actual = lower(await rpc(chainId, 'web3_sha3', [account.code]))
      method = 'pre-exploit transaction state'
    }
  } catch {
    // Some providers do not expose prestateTracer. A previous-block proof is
    // exact only for the first transaction in a block.
  }
  if (!actual && exploitAnchor.transactionIndex === 0 && exploitAnchor.blockNumber > 0) {
    try {
      const proof = await rpc(chainId, 'eth_getProof', [
        address,
        [],
        blockTag(exploitAnchor.blockNumber - 1),
      ])
      actual = lower(proof?.codeHash)
      method = 'previous block (exploit is transaction index 0)'
    } catch {
      // Report one fail-closed result below.
    }
  }
  if (!actual) {
    inconclusive(
      report,
      `${target.id}:code-hash`,
      'provider cannot expose the pre-exploit transaction code state; end-of-block state is not accepted',
    )
    return
  }
  if (actual !== expected)
    fail(report, `${target.id}:code-hash`, `${expected} != ${actual} (${method})`)
  else if (actual === EMPTY_CODE_HASH)
    fail(report, `${target.id}:code-hash`, 'artifact has the empty-code hash')
  else pass(report, `${target.id}:code-hash`, `${expected} (${method})`)
}

async function verifyCreateNonceProof(chainId, target, anchored, report) {
  const deployment = target.deployment
  const proof = deployment.creatorProof
  const label = `${target.id}:creator`
  if (deployment.blockNumber === 0) {
    fail(report, label, 'CREATE nonce proof cannot precede block zero')
    return
  }

  const encoded = createAddressInput(deployment.creatorAddress, proof.nonce)
  const derivedHash = await rpc(chainId, 'web3_sha3', [encoded])
  const derivedAddress = `0x${derivedHash.slice(-40)}`.toLowerCase()
  if (derivedAddress !== target.executionAddress) {
    fail(report, label, `CREATE nonce ${proof.nonce} derives ${derivedAddress}`)
    return
  }

  const beforeBlock = blockTag(deployment.blockNumber - 1)
  const atBlock = blockTag(deployment.blockNumber)
  const nonceBefore = hexInt(
    await rpc(chainId, 'eth_getTransactionCount', [deployment.creatorAddress, beforeBlock]),
  )
  const nonceAfter = hexInt(
    await rpc(chainId, 'eth_getTransactionCount', [deployment.creatorAddress, atBlock]),
  )
  if (nonceBefore > proof.nonce || nonceAfter <= proof.nonce) {
    fail(
      report,
      label,
      `creator nonce bounds ${nonceBefore} -> ${nonceAfter} do not contain ${proof.nonce}`,
    )
    return
  }

  const codeBefore = await rpc(chainId, 'eth_getCode', [target.executionAddress, beforeBlock])
  const codeAfter = await rpc(chainId, 'eth_getCode', [target.executionAddress, atBlock])
  if (codeBefore !== '0x' || codeAfter === '0x') {
    fail(report, label, 'execution-address code does not appear in the deployment block')
    return
  }

  const witness = anchored.receipt.logs.find(
    (log) => hexInt(log.logIndex) === proof.witnessLogIndex,
  )
  if (
    !witness ||
    lower(witness.address) !== target.executionAddress ||
    lower(witness.topics?.[0]) !== proof.eventTopic
  ) {
    fail(report, label, 'deployment receipt does not contain the declared execution-address witness')
    return
  }

  pass(
    report,
    label,
    `${deployment.creatorAddress} (CREATE nonce ${proof.nonce}, code appearance and receipt witness)`,
  )
}

async function verifyDeployment(chainId, target, report) {
  const deployment = target.deployment
  const anchored = await transactionAnchor(chainId, deployment, `${target.id}:deployment`, report)
  if (!anchored) return
  if (deployment.creatorAddress) {
    const receiptAddress = lower(anchored.receipt.contractAddress)
    const txSender = lower(anchored.tx.from)
    if (receiptAddress === target.executionAddress && txSender !== deployment.creatorAddress)
      fail(
        report,
        `${target.id}:creator`,
        `top-level creation sender ${txSender} != ${deployment.creatorAddress}`,
      )
    else if (receiptAddress === target.executionAddress)
      pass(report, `${target.id}:creator`, deployment.creatorAddress)
    else if (deployment.creatorProof) {
      try {
        await verifyCreateNonceProof(chainId, target, anchored, report)
      } catch (error) {
        inconclusive(report, `${target.id}:creator`, error.message)
      }
    }
    else {
      try {
        const trace = await rpc(chainId, 'debug_traceTransaction', [
          deployment.transactionHash,
          { tracer: 'callTracer', tracerConfig: { onlyTopCall: false, withLog: false } },
        ])
        const creation = collectTraceFrames(trace).find(
          ({ frame }) =>
            ['CREATE', 'CREATE2'].includes(String(frame.type).toUpperCase()) &&
            lower(frame.to) === target.executionAddress,
        )?.frame
        if (!creation)
          fail(report, `${target.id}:creator`, 'creation trace does not create executionAddress')
        else if (lower(creation.from) !== deployment.creatorAddress)
          fail(
            report,
            `${target.id}:creator`,
            `creation trace creator ${lower(creation.from)} != ${deployment.creatorAddress}`,
          )
        else pass(report, `${target.id}:creator`, `${deployment.creatorAddress} (creation trace)`)
      } catch (error) {
        inconclusive(report, `${target.id}:creator`, error.message)
      }
    }
  } else incomplete(report, `${target.id}:creator`, 'creatorAddress is null')
}

async function verifyAgeResetMechanism(chainId, target, anchored, report) {
  const reset = target.ageReset
  const mechanism = reset.mechanism
  const label = `${target.id}:age-reset-mechanism`
  if (mechanism.type === 'deployment') {
    if (
      reset.transactionHash !== target.deployment.transactionHash ||
      reset.blockNumber !== target.deployment.blockNumber
    )
      fail(report, label, 'deployment reset does not match the deployment anchor')
    else if (mechanism.address !== target.executionAddress)
      fail(
        report,
        label,
        `deployment mechanism address is not executionAddress ${target.executionAddress}`,
      )
    else pass(report, label, 'age reset is execution-address deployment')
    return
  }
  if (mechanism.type === 'event') {
    if (!mechanism.address || !mechanism.eventTopic || reset.logIndex === null) {
      incomplete(report, label, 'event mechanism requires address, eventTopic, and logIndex')
      return
    }
    const wanted = anchored.receipt.logs.find((log) => hexInt(log.logIndex) === reset.logIndex)
    if (!wanted) fail(report, label, `receipt has no logIndex ${reset.logIndex}`)
    else if (lower(wanted.address) !== mechanism.address || lower(wanted.topics?.[0]) !== mechanism.eventTopic)
      fail(report, label, 'recorded emitter/topic do not match the receipt log')
    else {
      pass(report, label, `event ${mechanism.eventTopic} emitted by ${mechanism.address}`)
      if (!mechanism.codeAddressLocation) {
        incomplete(
          report,
          `${target.id}:event-selection`,
          'event does not record where its payload selects the code artifact',
        )
      } else if (!target.codeArtifact.address)
        incomplete(report, `${target.id}:event-selection`, 'code artifact address is unknown')
      else {
        const selectedAddress = eventCodeAddress(wanted, mechanism.codeAddressLocation)
        if (selectedAddress !== target.codeArtifact.address)
          fail(
            report,
            `${target.id}:event-selection`,
            `event selected ${selectedAddress}, not ${target.codeArtifact.address}`,
          )
        else pass(report, `${target.id}:event-selection`, selectedAddress)
      }
    }
    return
  }
  if (mechanism.type === 'storage-write') {
    if (!mechanism.address || !mechanism.storageSlot || !mechanism.valueBefore || !mechanism.valueAfter) {
      incomplete(report, label, 'storage-write requires address, slot, valueBefore, and valueAfter')
      return
    }
    if (reset.blockNumber === 0) {
      fail(report, label, 'storage-write cannot be checked before block zero')
      return
    }
    const before = lower(
      await rpc(chainId, 'eth_getStorageAt', [
        mechanism.address,
        mechanism.storageSlot,
        blockTag(reset.blockNumber - 1),
      ]),
    )
    const after = lower(
      await rpc(chainId, 'eth_getStorageAt', [
        mechanism.address,
        mechanism.storageSlot,
        blockTag(reset.blockNumber),
      ]),
    )
    if (before !== mechanism.valueBefore || after !== mechanism.valueAfter)
      fail(report, label, `storage values ${before} -> ${after} do not match the record`)
    else {
      pass(report, label, `${mechanism.storageSlot}: ${before} -> ${after} at block boundaries`)
      try {
        const diff = await rpc(chainId, 'debug_traceTransaction', [
          reset.transactionHash,
          { tracer: 'prestateTracer', tracerConfig: { diffMode: true } },
        ])
        if (!diff?.pre || !diff?.post)
          throw new Error('prestateTracer did not return a diffMode pre/post result')
        const preAccount = keyedCaseInsensitive(diff?.pre, mechanism.address)
        const postAccount = keyedCaseInsensitive(diff?.post, mechanism.address)
        const preValue = keyedCaseInsensitive(preAccount?.storage, mechanism.storageSlot)
        const postValue = keyedCaseInsensitive(postAccount?.storage, mechanism.storageSlot)
        if (preValue === undefined && postValue === undefined) {
          fail(report, `${target.id}:storage-write-attribution`, 'transaction state diff does not change the declared slot')
        } else {
          const diffBefore = storageWord(preValue)
          const diffAfter = storageWord(postValue)
          if (diffBefore !== mechanism.valueBefore || diffAfter !== mechanism.valueAfter)
            fail(
              report,
              `${target.id}:storage-write-attribution`,
              `transaction state diff ${diffBefore} -> ${diffAfter} does not match the record`,
            )
          else
            pass(
              report,
              `${target.id}:storage-write-attribution`,
              `${reset.transactionHash} wrote the declared transition`,
            )
        }
      } catch (error) {
        inconclusive(report, `${target.id}:storage-write-attribution`, error.message)
      }
    }
    return
  }
  if (mechanism.type === 'view-call') {
    if (
      !mechanism.address ||
      !mechanism.callData ||
      !mechanism.valueBefore ||
      !mechanism.valueAfter
    ) {
      incomplete(report, label, 'view-call requires address, calldata, valueBefore, and valueAfter')
      return
    }
    if (reset.blockNumber === 0) {
      fail(report, label, 'view-call cannot be checked before block zero')
      return
    }
    const call = { to: mechanism.address, data: mechanism.callData }
    const before = lower(await rpc(chainId, 'eth_call', [call, blockTag(reset.blockNumber - 1)]))
    const after = lower(await rpc(chainId, 'eth_call', [call, blockTag(reset.blockNumber)]))
    if (before !== mechanism.valueBefore || after !== mechanism.valueAfter)
      fail(report, label, `view results ${before} -> ${after} do not match the record`)
    else pass(report, label, `${mechanism.callData}: ${before} -> ${after} at block boundaries`)
    return
  }
  if (mechanism.type === 'metamorphic-redeployment') {
    if (!mechanism.address) {
      incomplete(report, label, 'metamorphic redeployment requires an address')
      return
    }
    if (mechanism.address !== target.executionAddress) {
      fail(report, label, 'metamorphic redeployment address is not the executionAddress')
      return
    }
    try {
      const trace = await rpc(chainId, 'debug_traceTransaction', [
        reset.transactionHash,
        { tracer: 'callTracer', tracerConfig: { onlyTopCall: false, withLog: false } },
      ])
      const creation = collectTraceFrames(trace).find(
        ({ frame }) =>
          ['CREATE', 'CREATE2'].includes(String(frame.type).toUpperCase()) &&
          lower(frame.to) === mechanism.address,
      )?.frame
      if (!creation) {
        fail(report, label, 'redeployment trace does not create the declared address')
        return
      }

      const runtime = lower(creation.output)
      if (!runtime || runtime === '0x') {
        fail(report, label, 'redeployment trace does not return runtime code')
        return
      }
      const runtimeHash = lower(await rpc(chainId, 'web3_sha3', [runtime]))
      if (target.codeArtifact.address !== mechanism.address) {
        fail(report, label, 'metamorphic runtime is not the declared code artifact')
        return
      }
      if (runtimeHash !== target.codeArtifact.codeHash) {
        fail(
          report,
          label,
          `redeployed runtime hash ${runtimeHash} != ${target.codeArtifact.codeHash}`,
        )
        return
      }

      const prestate = await rpc(chainId, 'debug_traceTransaction', [
        reset.transactionHash,
        { tracer: 'prestateTracer', tracerConfig: { diffMode: false } },
      ])
      const account = keyedCaseInsensitive(prestate, mechanism.address)
      if (account?.code && account.code !== '0x') {
        fail(report, label, 'declared address still had code at transaction start')
        return
      }
      pass(
        report,
        label,
        `${String(creation.type).toUpperCase()} by ${lower(creation.from)} installed ${runtimeHash} at an empty address`,
      )
    } catch (error) {
      inconclusive(report, label, error.message)
    }
    return
  }
  incomplete(report, label, `mechanism ${mechanism.type} requires legacy/manual revalidation`)
}

async function verifyTarget(incident, target, exploitAnchor, report) {
  const chainId = incident.incident.chainId
  if (target.codeAgeSeconds !== incident.incident.exploit.timestamp - target.ageReset.timestamp)
    fail(report, `${target.id}:age`, 'codeAgeSeconds does not equal incident minus ageReset')
  else pass(report, `${target.id}:age`, `${target.codeAgeSeconds}s`)

  await verifyTrace(chainId, incident.incident.exploit.transactionHash, target, report)
  await verifyCodeHash(chainId, target, exploitAnchor, report)
  await verifyDeployment(chainId, target, report)

  const reset = await transactionAnchor(
    chainId,
    target.ageReset,
    `${target.id}:age-reset`,
    report,
  )
  if (reset) {
    const resetPosition = {
      blockNumber: reset.blockNumber,
      transactionIndex: reset.transactionIndex,
      logIndex: target.ageReset.logIndex,
    }
    const exploitPosition = {
      blockNumber: exploitAnchor.blockNumber,
      transactionIndex: exploitAnchor.transactionIndex,
      logIndex: -1,
    }
    if (comparePosition(resetPosition, exploitPosition) >= 0)
      fail(report, `${target.id}:ordering`, 'age reset is not strictly before the exploit transaction')
    else pass(report, `${target.id}:ordering`, 'age reset is strictly before the exploit')
    await verifyAgeResetMechanism(chainId, target, reset, report)
  }

  const attackers = new Set(
    [...incident.incident.attackerAddresses, lower(exploitAnchor.tx.from)].filter(Boolean),
  )
  if (target.deployment.creatorAddress && attackers.has(target.deployment.creatorAddress))
    fail(report, `${target.id}:creator-not-attacker`, 'creator is an attacker/exploit sender')
  else if (target.deployment.creatorAddress)
    pass(report, `${target.id}:creator-not-attacker`, target.deployment.creatorAddress)
  else incomplete(report, `${target.id}:creator-not-attacker`, 'creator is unknown')
}

async function verifyFile(file) {
  const incident = JSON.parse(readFileSync(file, 'utf8'))
  const report = createReport(file, incident)
  const chainId = incident.incident.chainId
  if (!rpcUrl(chainId)) {
    inconclusive(report, 'rpc', `no configured RPC for eip155:${chainId}`)
    return report
  }
  try {
    const exploit = await transactionAnchor(
      chainId,
      incident.incident.exploit,
      'exploit-transaction',
      report,
    )
    if (exploit) {
      for (const source of incident.sources ?? []) {
        if (source.type === 'onchain-transaction-set') {
          try {
            await verifyTransactionSet(source, report)
          } catch (error) {
            inconclusive(report, `${source.id}:transaction-set`, error.message)
          }
        }
      }
      for (const target of incident.targets) {
        try {
          await verifyTarget(incident, target, exploit, report)
        } catch (error) {
          inconclusive(report, `${target.id}:provider`, error.message)
        }
      }
    }
  } catch (error) {
    inconclusive(report, 'provider', error.message)
  }
  return report
}

function reportStatus(report, curveReady) {
  const statuses = new Set(report.checks.map((check) => check.status))
  if (statuses.has('FAIL')) return 'FAIL'
  if (statuses.has('INCONCLUSIVE')) return 'INCONCLUSIVE'
  if (statuses.has('INCOMPLETE')) return 'INCOMPLETE'
  if (
    curveReady &&
    (report.tier !== 'reviewed' ||
      report.targetVerification.some(
        (verification) =>
          verification.tier !== 'reviewed' || verification.curveEligible !== true,
      ))
  )
    return 'INCOMPLETE'
  return 'PASS_ANCHORS'
}

function printHuman(report, curveReady, quiet) {
  const status = reportStatus(report, curveReady)
  if (!quiet || status !== 'PASS_ANCHORS') {
    console.log(`${status.padEnd(12)} ${report.file} (${report.incidentId})`)
    if (!quiet) console.log(`  SCOPE        ${report.scope}`)
    for (const check of report.checks) {
      if (!quiet || check.status !== 'PASS')
        console.log(`  ${check.status.padEnd(12)} ${check.check}: ${check.detail}`)
    }
  }
  return status
}

const args = process.argv.slice(2)
const all = args.includes('--all')
const allowIncomplete = args.includes('--allow-incomplete')
const curveReady = args.includes('--curve-ready')
const quiet = args.includes('--quiet')
const json = args.includes('--json')
const files = all
  ? walkIncidentFiles(path.join(ROOT, 'incidents'))
  : args.filter((arg) => !arg.startsWith('--')).map((arg) => path.resolve(arg))

if (files.length === 0) {
  console.error(
    'usage: node scripts/verify.mjs incidents/<chainId>/<tx>.json | --all [--curve-ready] [--allow-incomplete] [--quiet] [--json]',
  )
  process.exit(1)
}

const reports = []
for (const file of files) {
  try {
    reports.push(await verifyFile(file))
  } catch (error) {
    const report = {
      file: path.relative(ROOT, file),
      incidentId: 'unknown',
      tier: undefined,
      targetVerification: [],
      scope: 'The file could not be loaded; no evidence was checked.',
      checks: [],
    }
    inconclusive(report, 'file', error.message)
    reports.push(report)
  }
}

if (json) console.log(JSON.stringify(reports, null, 2))
const tally = {}
for (const report of reports) {
  const status = json ? reportStatus(report, curveReady) : printHuman(report, curveReady, quiet)
  tally[status] = (tally[status] ?? 0) + 1
}
if (all && !json)
  console.log(`summary: ${Object.entries(tally).map(([status, count]) => `${status}=${count}`).join(' ')}`)

const contradictions = (tally.FAIL ?? 0) > 0
const incompleteEvidence = Object.keys(tally).some((status) => status !== 'PASS_ANCHORS')
process.exit(contradictions || (!allowIncomplete && incompleteEvidence) ? 1 : 0)
