# Methodology

This repository measures EVM code age when a contract vulnerability caused a
material exploit loss. Code age resets on executable-code changes and on causal
critical-state changes. Each measurement carries the onchain anchors and claim
evidence needed for independent review.

## Cohort

A primary incident satisfies three conditions:

1. A vulnerability in executed EVM code or persistent onchain configuration
   state caused the exploit.
2. A successful transaction that exercises the vulnerability or finalizes its
   loss, together with an implicated execution context, is identified onchain.
3. Stolen or permanently locked assets have an evidenced USD value or lower
   bound of at least 1,000.

Candidate records hold discovery leads, context incidents, and entries awaiting
one of these claims. The release lists every record, but the code-age curve
contains only reviewed incidents whose knot target is reviewed and
curve-eligible and whose loss has a concrete USD value.

A code defect is executable logic that violates an evidenced security invariant
under calls or inputs the deployed system permits. This includes missing or
incorrect authorization, accounting, validation, initialization, and external
interaction logic.

A configuration change is age-bearing when its persistent onchain state change
created the vulnerable condition later exercised by the exploit. The changed
value must be necessary to that condition, and its transaction and before/after
value must be anchored through a storage write or reproducible view call. Age
resets at that change even when the code applies the value as designed. A safer
parameter value or parameter-only mitigation does not decide attribution.

Exclude losses caused only by compromised credentials, direct privileged
transfers or drains, market conditions, or offchain/front-end behavior. A
privileged action or credential compromise is not itself an incident; a
persistent state change it makes can qualify only when it creates a vulnerability
exercised by a later transaction. Values that only change exposure or loss size
do not reset age.

## Incident and target units

An incident is one fault episode: every exploitation of one vulnerability in
one code artifact, from its first successful exercise until the code was fixed.
Anchor it to the earliest successful transaction that exercises the
vulnerability, or to the transaction that makes a permanent loss final when
there is no earlier successful exploit. The incident owns the summary, one knot,
and a loss not counted by another record.

Repeated transactions, later actors repeating the exploit against the same
code, and same-campaign legs against byte-identical deployments on other chains
all belong to that one incident: code already shown vulnerable does not fail a
second time, it loses more. Each merged campaign adds its own loss components
and sources, `realizedAt` marks the end of the last one, and a note names when
and by whom it happened. Targets are the contracts the anchor transaction
executed; a deployment exercised only later or on another chain is described in
the note. A different vulnerability, or the same vulnerability in another
codebase exploited in a separate campaign, is a separate incident.

A target is an independently aged execution context and code artifact implicated
in that incident. It distinguishes:

- `executionAddress`: the address supplying storage and authority;
- `codeArtifact`: the implementation, facet, module, library, or direct
  runtime containing the defect or consuming the causal state;
- `relationship`: how the execution context reached the artifact;
- `ageReset`: the latest code or causal configuration change that established
  the vulnerable state.

Add a target for every defect-bearing artifact the anchor executed: price
sources, entry points, and sibling deployments of one template, which differ
only in their deployment arguments. One target may represent many siblings when
the loss evidence covers the full campaign, and an incident has at most one
target per exact `(codeArtifact.codeHash, failureModeId)` pair.

An incident contributes one knot. Exactly one target is `curveEligible`: the
one with the latest age reset, because the exploitable combination came into
existence at that reset. This holds whether the targets composed one failure -
an oracle and its consumer, a reentrancy window and the pricing it corrupts,
sibling runtimes repeating one defect - or exploited independent defects in one
transaction. The other targets remain reviewed evidence and say in a limitation
why they are not the knot.

## Code age

For each target:

```text
codeAgeSeconds = incident.exploit.timestamp - ageReset.timestamp
```

`ageReset` is the latest pre-exploit onchain change that established the
vulnerable code-and-critical-state combination. It is the latest executable-code
activation unless a later causal configuration change reset the clock. Ordering
uses `(blockNumber, transactionIndex, logIndex)`.

Supported mechanisms include deployment, implementation or beacon changes,
diamond cuts, module or route installation, code-selecting storage writes, and
metamorphic redeployment. A configuration reset identifies either an exact
storage write or raw calldata and return data before and after the reset. Event
anchors for code changes identify the event topic and the exact topic or data
word containing the selected code address.

The age basis is the victim code and critical configuration state immediately
before exploit execution. Attacker-installed exploit machinery receives
explicit attribution. A qualifying reset must strictly precede the exploit
transaction.

Code introduced shortly before a later drain is presumed attack machinery when
it directs assets to a fixed attacker or exposes an attacker-only drain. Its
introduction is the attack, not an age reset for the later payout. Admit the
incident only if an independent victim-code or causal-configuration defect made
that introduction possible, and age that defect to its first successful use.

An unprotected initializer left reachable on a deployed proxy is a defect in
that deployed code, exploitable and publicly visible from the moment it is
installed. Such an incident anchors on the earliest transaction that calls the
initializer, so the age spans the interval the defect survived unexploited, and
a later drain through attacker-installed implementations belongs to the loss
rather than to the age.

Shared code is aged from when the artifact became active for the execution
context that ran it. Where the context reads a mutable pointer - a beacon, a
diamond's routing, a router's module table - that is the activation event, and a
per-user account created moments before the exploit does not reset the age of
the template it delegates to. Where the pointer is fixed at creation, as in an
EIP-1167 clone, the default is the clone's own creation. `deployment` anchors the
execution context throughout; `ageReset` anchors the measured state.

A clone can reasonably be aged either from itself or from the logic it copies,
and the record decides case by case and says which in its review note. Prefer
the clone when the defect only became reachable through that instance - the
token it was configured with, or the balance it accumulated - because a latent
flaw in shared logic is exploited when a particular deployment makes it worth
exploiting. Prefer the shared logic when the instance adds nothing that bears on
the defect.

An age basis requires positive evidence that the relevant code and critical
state continued through the exploit. Suitable evidence depends on architecture
and can combine runtime hashes, implementation or beacon slots, custom events,
storage history, and execution traces.

When historical internal-creation traces are unavailable, a CREATE creator can
be established by address derivation, creator nonce bounds, code appearance in
the deployment block, and a deployment-receipt witness from the created address.
Genesis system code has no deployment transaction. Anchor it as
`system-genesis` at block zero and verify that block's timestamp and runtime hash.

## Verification

Verification follows the ownership of each claim:

- Incident `provisional`: exploit anchor, summary, or loss awaits review.
- Incident `reviewed`: exploit anchor, vulnerability summary, and loss have been
  reviewed. Only reviewed incidents become curve rows.
- Target `provisional`: artifact identity or age history awaits research.
- Target `reviewed`: execution relationship, artifact hash, failure identity,
  exact anchors, and age-history completeness have been reviewed.

An incident reaches the curve when it is reviewed and its curve-eligible
target is reviewed. Each target is promoted independently.

Every reviewed claim links to a `review-note` attestation with a reviewer and
review time. Incident attestations cover anchor, root cause, and loss; target
attestations cover artifact identity and complete age history.

The verifier reports `PASS_ANCHORS`, `FAIL`, `INCOMPLETE`, or
`INCONCLUSIVE`. `PASS_ANCHORS` certifies the bounded mechanical checks.
Provider and unsupported-method outcomes are `INCONCLUSIVE`.

## Loss

Loss is the value stolen or permanently locked because of the vulnerability.
`kind` states whether the measurement is gross assets lost, net loss, or
permanently locked value. Prefer exact pre-recovery victim depletion when it can
be isolated. Identifiable attacker-supplied campaign inputs are not victim loss;
financing fees, builder payments, and later recoveries do not reduce gross
victim depletion. Use net loss only when gross victim depletion cannot be
separated, and state how every adjustment is treated.

A loss covers every campaign merged into the incident, each measured by its
own components and sources, and is never duplicated across records. The
incident anchor fixes the code-age timestamp; `realizedAt` records a later
campaign end when needed.

Evidence can combine onchain transactions, project reports, technical
post-mortems, and reputable published analysis. Reported estimates state their
scope and valuation method.

Reviewed asset components identify the chain and token, decimal quantity, USD
value, valuation timestamp and method, and evidence IDs. Use
`realised-proceeds` when the measured quantity or effective unit value comes
from the attacker's disposal; it is required when that disposal moved the price.
An aggregate that combines realised proceeds with another basis uses `other`.
Stable assets may use 1:1 valuation. Liquid assets use a timestamped price
source. Illiquid assets use an evidenced lower bound when it establishes cohort
admission. `price-data` sources record provider, URL, and evidence-retrieval time
in `observedAt`; the asset valuation's `timestamp` is the historical price time.

Provisional records may carry an `unspecified` loss kind and prose asset
descriptions imported from a discovery source. Reviewed records use structured
components and high or medium confidence.

An evidenced `minimumUsd` lower bound is enough for dataset admission when an
exact valuation is unavailable. It is not enough for the comparable curve,
which requires `loss.usd.amount >= 1,000`.

## Curve construction

Each reviewed incident with a reviewed, curve-eligible target and a concrete
USD loss is one curve row carrying that target's age and the incident's loss.
The checker rejects a second curve-eligible target in one incident, and rejects
the same `failure:<namespace>` identifier knotted on the same runtime hash in
two incidents: such records merge, or one of them names a distinct defect. A
distinct vulnerability in identical bytecode receives a distinct identifier.

`dist/latest/incidents.json` publishes the rows sorted by age and every other
record with its `exclusionReasons`.

## Provenance and releases

Claims link directly to evidence source IDs. Repository evidence records a
repository, path, and full 40-character commit. Onchain evidence records EIP-155
chain and transaction coordinates.

`research/candidates.json` assigns every discovery entry an included, excluded,
out-of-scope, pending, or unresolved disposition. Generated releases include
source hashes and a manifest; incident files remain authoritative.
