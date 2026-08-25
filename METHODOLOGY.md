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
one of these claims. The curve contains the reviewed subset of primary
incidents.

## Incident and target units

An incident is anchored to one successful exploit or failure-finalizing
transaction and owns the classification and loss measurement.

A target is an independently aged execution context and code artifact implicated
in that incident. It distinguishes:

- `executionAddress`: the address supplying storage and authority;
- `codeArtifact`: the implementation, facet, module, library, or direct
  runtime containing the defect;
- `relationship`: how the execution context reached the artifact;
- `lastCodeChange`: the change that made the artifact active.

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

- Incident `provisional`: classification or loss awaits review.
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
locked value.

A loss spanning several transactions or chains is one incident when they form a
coherent campaign caused by the same defect. The incident anchor fixes the
code-age timestamp; the loss covers the campaign. Evidence can combine onchain
transactions, project reports, technical post-mortems, and reputable published
analysis. Reported estimates state their scope and valuation method.

Reviewed asset components identify the chain and token, decimal quantity, USD
value, valuation timestamp and method, and evidence IDs. Stable assets may use
1:1 valuation. Liquid assets use a timestamped price source. Illiquid assets use
an evidenced lower bound when it establishes cohort admission. `price-data`
sources record provider, URL, and observation time.

Legacy asset prose remains a provisional migration representation. Reviewed
records use structured components and high or medium confidence.

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
