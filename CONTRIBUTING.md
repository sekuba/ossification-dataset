# Contributing

`METHODOLOGY.md` defines cohort admission, code age, verification, loss, and
curve construction.

## Workflow

1. Add discovery leads to the research inputs and assign a candidate
   disposition.
2. Create `incidents/<chainId>/<exploitTx>.json` after establishing the cohort
   admission claims.
3. Add one target for every independently aged code state.
4. Link incident and target claims to evidence source IDs.
5. Run the onchain verifier and promote each claim at its achieved tier.
6. Regenerate and review `dist/latest/`.

## Incident evidence

Establish:

- the successful exploit transaction and execution context;
- the EVM code defect and causal root-cause evidence;
- stolen or permanently locked assets valued at USD 1,000 or more;
- structured loss kind, components, valuation, confidence, and source IDs.

The incident owns classification and loss.

## Target evidence

Record:

- `executionAddress`, `relationship`, and defect-bearing `codeArtifact`;
- runtime code hash;
- deployment transaction and creator;
- latest pre-exploit executable-code change;
- exact block, transaction index, and log index;
- mechanism-specific event, storage, creation, or trace evidence;
- identity and code-history source IDs;
- reviewed `failure:<namespace>` identity when available.

Proxy and modular targets retain both execution context and code-artifact roles.
Event changes identify the exact topic or data word selecting the code address.
Deployment-based ages include positive continuity evidence.

## Promotion

Claims begin as `provisional`. Automated anchor reproduction promotes a target
to `mechanical`. Semantic review promotes the incident or target to
`reviewed`. A reviewed target under a reviewed incident becomes
`curveEligible` when every curve condition holds.

## Validation

Use Node 22.

```bash
npm test
npm run verify -- incidents/<chainId>/<file>.json --curve-ready
npm run build
```

Review observation IDs, cohort counts, exclusion reasons, and source hashes in
`dist/latest/`.
