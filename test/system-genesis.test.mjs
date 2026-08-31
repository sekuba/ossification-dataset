import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import { validateSchema } from '../scripts/check.mjs'

const schema = JSON.parse(readFileSync(new URL('../schema/incident.schema.json', import.meta.url)))
const deploymentSchema = schema.$defs.deploymentAnchor

function errors(deployment) {
  return validateSchema(deployment, deploymentSchema, schema)
}

test('system-genesis accepts only an exact block-zero state anchor', () => {
  assert.deepEqual(errors({ kind: 'system-genesis', timestamp: 1_590_824_836, blockNumber: 0 }), [])

  for (const extra of [
    { transactionHash: `0x${'01'.repeat(32)}` },
    { transactionIndex: 0 },
    { creatorAddress: `0x${'01'.repeat(20)}` },
    {
      creatorProof: {
        type: 'create-nonce',
        nonce: 0,
        witnessLogIndex: 0,
        eventTopic: `0x${'01'.repeat(32)}`,
      },
    },
  ]) assert.notDeepEqual(errors({ kind: 'system-genesis', timestamp: 1, blockNumber: 0, ...extra }), [])

  assert.notDeepEqual(errors({ kind: 'system-genesis', timestamp: 1, blockNumber: 1 }), [])
})

test('transaction deployment anchors remain valid', () => {
  assert.deepEqual(errors({
    timestamp: 1,
    blockNumber: 1,
    transactionHash: `0x${'01'.repeat(32)}`,
    transactionIndex: 0,
    creatorAddress: `0x${'01'.repeat(20)}`,
  }), [])
})
