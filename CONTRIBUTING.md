# Contributing

`METHODOLOGY.md` defines cohort admission, code age, verification, loss, and
curve construction.

## Workflow

1. Add discovery leads to the research inputs, and claim the lead a record
   answers in its `discovery` field.
2. Establish the EVM vulnerability, onchain-anchor, and USD-loss admission
   claims.
3. Create one `incidents/<chainId>/<exploitTx>.json` per affected same-chain
   campaign. Keep different chains and separate campaigns distinct; a coherent
   mass campaign may use the representative-target rule. Never duplicate loss.
4. Add targets under the representative rule in `METHODOLOGY.md`, then link
   each claim to evidence source IDs.
5. Run the onchain verifier and promote only the claims actually reproduced and
   reviewed. Link semantic review to an attestation naming the reviewer and
   review time.
6. Regenerate and review `dist/latest/`.

## Review checklist

For the incident, establish:

- the successful exploit transaction and execution context;
- the EVM code or persistent-state vulnerability and causal evidence;
- stolen or permanently locked assets valued at USD 1,000 or more;
- structured loss kind, components, valuation, confidence, and source IDs.

For each target, establish:

- `executionAddress`, `relationship`, and implicated `codeArtifact`;
- runtime code hash;
- deployment transaction and creator;
- latest pre-exploit age reset: deployment, code change, or causal
  configuration change;
- exact block, transaction index, and log index;
- mechanism-specific event, storage, view-call, creation, or trace evidence;
- identity and age-history source IDs;
- reviewed `failure:<namespace>` identity when available.

Claims begin as `provisional`. Reproducing anchors with the verifier is not
semantic review. Set incident or target `reviewed` only after linking a
`review-note` with `reviewer` and `reviewedAt` through
`verification.reviewSourceIds`. Set `curveEligible` only when all curve rules in
`METHODOLOGY.md` hold.

## Discovery leads

`research/candidates.json` marks a lead covered only when an incident claims it.
Set `discovery` to the candidate ids a record answers, for example
`["web:2021-05-29:belt-finance"]`. Ids come from `research/candidates.json`; a
campaign spanning several chains has one lead claimed by each chain's incident.
The field is research bookkeeping and supports no claim.

## Known follow-ups

Open work is a query over the records, never a hand-maintained list, so it
cannot go stale:

```bash
# loss notes describe realised proceeds while loss.usd.method says otherwise;
# relabel to realised-proceeds where that is genuinely the basis used
grep -rlE 'realis(ed|ation)|realiz(ed|ation)' incidents | xargs grep -Ll '"method": "realised-proceeds"'

# re-examine configuration exclusions under causal critical-state age resets
jq -r '.entries[] | select(.reason | test("^CONFIGURATION_(ERROR|AND_MARKET):|parameter value|parameter-value"; "i")) | .name' research/raw/exclusions.json
```

## Validation

Use Node 22.

```bash
npm test
npm run verify -- incidents/<chainId>/<file>.json --curve-ready
npm run build
```

Review observation IDs, cohort counts, exclusion reasons, and source hashes in
`dist/latest/`.
