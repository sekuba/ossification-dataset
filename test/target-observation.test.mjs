import assert from 'node:assert/strict'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { buildArtifacts } from '../scripts/build.mjs'
import { checkIncidentCrossFields, validateSchema } from '../scripts/check.mjs'

const ROOT = path.dirname(new URL('../package.json', import.meta.url).pathname)
const hash = (byte) => `0x${byte.repeat(64)}`
const address = (byte) => `0x${byte.repeat(40)}`

function fixture() {
  return {
    $schema: '../../schema/incident.schema.json',
    id: `eip155:1:${hash('1')}`,
    protocol: { name: 'Fixture', slug: 'fixture' },
    name: 'target observation fixture',
    incident: {
      chainId: 1,
      exploit: { transactionHash: hash('1'), blockNumber: 10, transactionIndex: 0, timestamp: 100 },
      attackerAddresses: [address('a')],
    },
    summary: 'Two distinct runtimes first execute at different times in one campaign.',
    loss: {
      kind: 'gross-assets-lost',
      usd: { amount: 1000, valuationTimestamp: 100, method: 'stablecoin-par', sourceIds: ['source-1'] },
      assets: [{
        asset: { chainId: 1, tokenAddress: address('9'), symbol: 'USD' },
        amount: '1000',
        usdValue: 1000,
        valuation: { method: 'stablecoin-par', timestamp: 100, unitPriceUsd: 1, sourceIds: ['source-1'] },
        sourceIds: ['source-1'],
      }],
      confidence: 'high',
      notes: 'Fixture loss is owned once by the incident.',
    },
    targets: [
      {
        id: 'target-1', executionAddress: address('1'), relationship: 'direct',
        codeArtifact: { address: address('1'), codeHash: hash('a') },
        deployment: { timestamp: 10, blockNumber: 1, transactionHash: hash('3'), transactionIndex: 0, creatorAddress: address('3') },
        ageReset: { kind: 'deployment' }, codeAgeSeconds: 90,
        failureModeId: 'failure:fixture-common',
        evidence: { identitySourceIds: ['source-1', 'source-3'], ageSourceIds: ['source-3'] },
        verification: { tier: 'reviewed', curveEligible: true, limitations: [], reviewSourceIds: ['source-5'] },
      },
      {
        id: 'target-2', executionAddress: address('2'), relationship: 'direct',
        curveRole: 'supporting',
        observation: { transactionHash: hash('2'), blockNumber: 20, transactionIndex: 1, timestamp: 200 },
        codeArtifact: { address: address('2'), codeHash: hash('b') },
        deployment: { timestamp: 20, blockNumber: 2, transactionHash: hash('4'), transactionIndex: 0, creatorAddress: address('4') },
        ageReset: { kind: 'deployment' }, codeAgeSeconds: 180,
        failureModeId: 'failure:fixture-common',
        evidence: { identitySourceIds: ['source-2', 'source-4'], ageSourceIds: ['source-4'] },
        verification: { tier: 'reviewed', curveEligible: false, limitations: ['Correlated supporting target.'], reviewSourceIds: ['source-5'] },
      },
    ],
    sources: [
      { id: 'source-1', type: 'onchain-transaction', chainId: 1, transactionHash: hash('1') },
      { id: 'source-2', type: 'onchain-transaction', chainId: 1, transactionHash: hash('2') },
      { id: 'source-3', type: 'onchain-transaction', chainId: 1, transactionHash: hash('3') },
      { id: 'source-4', type: 'onchain-transaction', chainId: 1, transactionHash: hash('4') },
      { id: 'source-5', type: 'review-note', reviewer: 'test', reviewedAt: '2026-08-31T00:00:00Z', note: 'fixture review' },
    ],
    verification: { tier: 'reviewed', limitations: [], reviewSourceIds: ['source-5'] },
  }
}

test('one loss owns its canonical observation and a later correlated supporting target', () => {
  const incident = fixture()
  const schema = JSON.parse(readFileSync(path.join(ROOT, 'schema/incident.schema.json')))
  assert.deepEqual(validateSchema(incident, schema), [])
  assert.deepEqual(checkIncidentCrossFields(incident), [])

  const root = mkdtempSync(path.join(tmpdir(), 'target-observation-'))
  try {
    mkdirSync(path.join(root, 'incidents/1'), { recursive: true })
    mkdirSync(path.join(root, 'schema'), { recursive: true })
    writeFileSync(path.join(root, `incidents/1/${hash('1')}.json`), `${JSON.stringify(incident, null, 2)}\n`)
    for (const name of ['incident.schema.json', 'release-incidents.schema.json', 'release-curve.schema.json', 'release-manifest.schema.json'])
      cpSync(path.join(ROOT, 'schema', name), path.join(root, 'schema', name))
    const build = buildArtifacts(root)
    assert.equal(build.values.incidents.incidents.length, 1)
    assert.equal(build.values.incidents.incidents[0].loss.usd.amount, 1000)
    assert.deepEqual(
      build.values.curve.observations.map((entry) => [entry.exploit.timestamp, entry.codeAgeSeconds]),
      [[100, 90]],
    )
    assert.ok(build.values.curve.observations.every((entry) => !Object.hasOwn(entry, 'loss')))
    assert.equal(build.values.curve.otherExcludedObservations.length, 1)
    assert.equal(build.values.curve.otherExcludedObservations[0].curveRole, 'supporting')
    assert.deepEqual(
      build.values.curve.otherExcludedObservations[0].exclusionReasons,
      ['target-role:supporting-correlated'],
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('target observation rejects missing linkage and incident-anchored age', () => {
  const missing = fixture()
  missing.sources = missing.sources.filter((source) => source.id !== 'source-2')
  assert.ok(checkIncidentCrossFields(missing).some((error) => error.includes('observation transaction must have an onchain source')))

  const unlinked = fixture()
  unlinked.targets[1].evidence.identitySourceIds = ['source-4']
  assert.ok(checkIncidentCrossFields(unlinked).some((error) => error.includes('observation transaction source must be linked')))

  const wrongAge = fixture()
  wrongAge.targets[1].codeAgeSeconds = 80
  assert.ok(checkIncidentCrossFields(wrongAge).some((error) => error.includes('observation.timestamp - ageReset.timestamp')))
})

test('supporting role rejects eligible, orphaned, and different-failure targets', () => {
  const eligible = fixture()
  eligible.targets[1].verification.curveEligible = true
  assert.ok(checkIncidentCrossFields(eligible).some((error) => error.includes('supporting target must be reviewed and not curve-eligible')))

  const orphaned = fixture()
  orphaned.targets = [orphaned.targets[1]]
  assert.ok(checkIncidentCrossFields(orphaned).some((error) => error.includes('supporting target requires a reviewed curve-eligible sibling')))

  const differentFailure = fixture()
  differentFailure.targets[0].failureModeId = 'failure:fixture-different'
  assert.ok(checkIncidentCrossFields(differentFailure).some((error) => error.includes('supporting target requires a reviewed curve-eligible sibling')))
})
