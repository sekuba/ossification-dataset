# Methodology

This repository measures the age of EVM code when a defect in that code caused a
material exploit loss. Each measurement carries the onchain anchors and claim
evidence needed for independent review.

## Cohort

A primary incident satisfies three conditions:

1. A defect in executed EVM code caused the exploit.
2. A successful transaction that executes the defect or finalizes its loss,
   together with an implicated execution context, is identified onchain.
3. Stolen or permanently locked assets have an evidenced USD value or lower
   bound of at least 1,000.

Candidate records hold discovery leads, context incidents, and entries awaiting
one of these claims. The release retains every admitted target, but the
executable-code curve contains only reviewed, curve-eligible target
observations with a concrete USD loss.

A code defect is executable logic that violates an evidenced security invariant
under calls or inputs the deployed system permits. This includes missing or
incorrect authorization, accounting, validation, initialization, and external
interaction logic. Exclude losses caused only by compromised credentials,
malicious or mistaken privileged actions, configured parameter values that the
code applies as designed, market conditions, or offchain/front-end behavior.
In a mixed case, admit the incident only when the executed EVM code itself
failed an evidenced invariant; configuration changes remain context, not the
code-age anchor.

## Incident and target units

An incident represents one coherent campaign against an affected execution
context on one chain. Anchor it to the earliest successful transaction in the
campaign that executes the defect, or to the transaction that makes a permanent
loss final when there is no earlier defect-executing success. The incident owns
the classification and a loss measurement not counted by another record.

Repeated transactions in one coherent campaign on the same chain belong to one
incident. Such a campaign may span code-identical deployments under the
representative-target rule below. A campaign on a different chain, or a
separate campaign against another deployment, is a separate incident because
its anchors, age, and loss are independent. When one incident implicates
several distinct defect-bearing code states, represent them as targets of that
incident. Curve deduplication handles code-identical repetitions across
incidents; it does not merge their source records or losses.

A target is an independently aged execution context and code artifact implicated
in that incident. It distinguishes:

- `executionAddress`: the address supplying storage and authority;
- `codeArtifact`: the implementation, facet, module, library, or direct
  runtime containing the defect;
- `relationship`: how the execution context reached the artifact;
- `lastCodeChange`: the change that made the artifact active.

An incident has at most one target for each exact
`(codeArtifact.codeHash, failureModeId)` pair. If a same-chain campaign exploits
many code-identical deployments through the same failure, use the execution
context first reached by the anchored campaign as the representative target and
cover the full campaign in the loss evidence. Add targets for distinct code or
failure pairs and for distinct defect-bearing roles in the causal path.

This representation covers direct contracts, proxies, beacons, clones,
diamonds, routers, shared implementations, and libraries.

## Code age

For each target:

```text
codeAgeSeconds = incident.timestamp - lastCodeChange.timestamp
```

`lastCodeChange` is the latest pre-exploit onchain change to the executable
code used by the target. Ordering uses
`(blockNumber, transactionIndex, logIndex)`.

Supported mechanisms include deployment, implementation or beacon changes,
diamond cuts, module or route installation, code-selecting storage writes, and
metamorphic redeployment. Event anchors identify the event topic and the exact
topic or data word containing the selected code address.

The age basis is the victim code state immediately before exploit execution.
Attacker-installed exploit machinery receives explicit attribution. The
executable-code curve uses deployment, implementation, and module changes;
parameter, market, and exposure changes are retained as configuration context.

An unprotected initializer left reachable on a deployed proxy is a defect in
that deployed code, exploitable and publicly visible from the moment it is
installed. Such an incident anchors on the earliest transaction that calls the
initializer, so the age spans the interval the defect survived unexploited, and
a later drain through attacker-installed implementations belongs to the loss
rather than to the age.

A deployment basis requires positive evidence that the relevant code state
continued through the exploit. Suitable evidence depends on architecture and
can combine runtime hashes, implementation or beacon slots, custom events,
storage history, and execution traces.

## Verification

Verification follows the ownership of each claim:

- Incident `provisional`: exploit anchor, classification, or loss awaits review.
- Incident `reviewed`: exploit anchor, code-bug classification, and loss have
  been reviewed.
- Target `provisional`: artifact identity or code history awaits research.
- Target `mechanical`: the automated verifier reproduced the declared
  anchors.
- Target `reviewed`: execution relationship, artifact hash, failure identity,
  exact anchors, and code-history completeness have been reviewed.

A curve observation requires a reviewed incident and a reviewed target with
`curveEligible: true`. Each target is promoted independently.

Every reviewed claim links to a `review-note` attestation with a reviewer and
review time. Incident attestations cover anchor, root cause, and loss; target
attestations cover artifact identity and complete code history.

The verifier reports `PASS_ANCHORS`, `FAIL`, `INCOMPLETE`, or
`INCONCLUSIVE`. `PASS_ANCHORS` certifies the bounded mechanical checks.
Provider and unsupported-method outcomes are `INCONCLUSIVE`.

## Loss

Loss is the value stolen or permanently locked because of the defect. `kind`
states whether the measurement is gross assets lost, net loss, or permanently
locked value. Prefer exact pre-recovery victim depletion when it can be
isolated. Identifiable attacker-supplied campaign inputs are not victim loss;
financing fees, builder payments, and later recoveries do not reduce gross
victim depletion. Use net loss only when gross victim depletion cannot be
separated, and state how every adjustment is treated.

A loss spanning several transactions in the same incident covers the coherent
campaign. Cross-chain or separate-deployment losses belong to their respective
incident records and must not be duplicated. The incident anchor fixes the
code-age timestamp; `realizedAt` records a later campaign end when needed.
Evidence can combine onchain transactions, project reports, technical
post-mortems, and reputable published analysis. Reported estimates state their
scope and valuation method.

Reviewed asset components identify the chain and token, decimal quantity, USD
value, valuation timestamp and method, and evidence IDs. Stable assets may use
1:1 valuation. Liquid assets use a timestamped price source. Illiquid assets use
an evidenced lower bound when it establishes cohort admission. `price-data`
sources record provider, URL, and evidence-retrieval time in `observedAt`; the
asset valuation's `timestamp` is the historical price time.

Legacy asset prose remains a provisional migration representation. Reviewed
records use structured components and high or medium confidence.

An evidenced `minimumUsd` lower bound is enough for dataset admission when an
exact valuation is unavailable. It is not enough for the comparable curve,
which requires `loss.usd.amount >= 1,000`.

## Curve construction

Eligible targets are grouped by exact
`(codeArtifact.codeHash, failureModeId)`. The earliest reviewed exploit in
each group supplies the curve observation.

For complete anchors on one chain, selection uses block number and transaction
index. Cross-chain or incomplete comparisons use timestamp, chain ID, incident
ID, and target ID. A distinct defect in identical bytecode receives a distinct
reviewed `failure:<namespace>` identifier.

`dist/latest/curve.json` publishes selected observations, deduplicated
observations, exclusions, and sorted `ageKnots`. Each observation references
its incident-level loss through `incidentId`. `research/revalidation.json`
publishes the deterministic blocker list for every target.

## Provenance and releases

Evidence sources declare the claims they support. Target evidence links identity
and code-history claims to source IDs. Repository evidence records repository,
path, and a full 40-character commit. Onchain evidence records EIP-155 chain and
transaction coordinates.

`research/candidates.json` assigns every discovery entry an included, excluded,
out-of-scope, pending, or unresolved disposition. Generated releases include
source hashes and a manifest; incident files remain authoritative.
