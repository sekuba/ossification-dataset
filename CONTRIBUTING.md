# Contributing

`METHODOLOGY.md` defines cohort admission, code age, verification, loss, and
curve construction.

## Workflow

1. Add discovery leads to the research inputs and assign a candidate
   disposition.
2. Establish the code-defect, onchain-anchor, and USD-loss admission claims.
3. Create one `incidents/<chainId>/<exploitTx>.json` per affected same-chain
   campaign. Keep separate deployments or chains separate and never duplicate
   their losses.
4. Add targets under the representative rule in `METHODOLOGY.md`, then link
   each claim to evidence source IDs.
5. Run the onchain verifier and promote only the claims actually reproduced and
   reviewed. Link semantic review to an attestation naming the reviewer and
   review time.
6. Regenerate and review `research/revalidation.json` and `dist/latest/`.

## Review checklist

For the incident, establish:

- the successful exploit transaction and execution context;
- the EVM code defect and causal root-cause evidence;
- stolen or permanently locked assets valued at USD 1,000 or more;
- structured loss kind, components, valuation, confidence, and source IDs.

For each target, establish:

- `executionAddress`, `relationship`, and defect-bearing `codeArtifact`;
- runtime code hash;
- deployment transaction and creator;
- latest pre-exploit executable-code change;
- exact block, transaction index, and log index;
- mechanism-specific event, storage, creation, or trace evidence;
- identity and code-history source IDs;
- reviewed `failure:<namespace>` identity when available.

Claims begin as `provisional`. `mechanical` means the verifier reproduced the
target anchors; it is not semantic review. Set incident or target `reviewed`
only after linking a `review-note` with `reviewer` and `reviewedAt` through
`verification.reviewSourceIds`. Set `curveEligible` only when all curve rules in
`METHODOLOGY.md` hold.

## Validation

Use Node 22.

```bash
npm test
npm run verify -- incidents/<chainId>/<file>.json --curve-ready
npm run revalidation
npm run build
```

Review observation IDs, cohort counts, exclusion reasons, and source hashes in
`dist/latest/`.
