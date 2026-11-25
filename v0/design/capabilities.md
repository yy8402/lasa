# Capability model

## Meaning and identity

A capability is a contract for an observable outcome from an input, subject to stated preconditions, effects, limits, and failure semantics. It is neither a tool nor an assertion that every admissible request succeeds. For example, `design.review` produces a bounded review against explicit criteria; it does not promise a mathematically correct design. A generic `task.attempt` promises a bounded attempt and an honest disposition, not expertise in every subject.

An identifier is an absolute HTTPS URI under a publisher-controlled namespace, independent of service location. It is an identifier, not an instruction to fetch a URL. An exact reference contains `id`, `version`, and `digest`. Versions use `MAJOR.MINOR.PATCH` without ranges on the wire. Any change to a published definition creates a new version; incompatible meaning, input requirements, effects, or success conditions require a new major. Minor/patch distinctions document publisher intent and never authorize automatic substitution.

`digest` is `sha256:` followed by the SHA-256 of the complete definition encoded with RFC 8785 JSON canonicalization. The definition does not contain its own digest. JSON must satisfy the canonicalization domain; duplicate keys, non-finite numbers, and unsafe numeric representations are rejected. Digests identify bytes/semantics chosen by a trusted publisher; an unauthenticated hash does not authenticate the publisher. [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)

Each definition includes:

- Outcome and observable postconditions, including what counts as completion and what the contract does not guarantee.
- JSON Schema 2020-12 input and output schemas, precondition predicates, and the evidence required to check them.
- An effect ceiling: private workspace mutations, external reads, or external writes, with named resource/action patterns. Destructive effects cannot hide behind prose.
- Failure codes and retry safety, plus whether a partially completed or uncertain external effect can occur.
- Verification obligations and boundedness requirements. Runtime quotas and commercial terms belong to offers, not immutable definitions.

The contract bundle defines the shape of a definition; its embedded input/output schemas define task-specific data. Schema references in a definition must be fragment-local to that embedded schema. Remote references, executable validators, and arbitrary schema fetching are forbidden. Portable predicates use the closed kinds `input_schema`, `resource_authorized`, `artifact_present`, `budget_minimum`, and `semantic_review`. Semantic predicates require recorded judgment and may remain unknown; a schema validator cannot decide them.

## Five separate objects

| Object | Owner | Scope and lifetime | Meaning |
|---|---|---|---|
| `CapabilityDefinition` | Trusted contract publisher | Immutable exact version | What a successful outcome means |
| `FulfillmentBinding` | Service administrator, private | Local configuration revision | Approved local executor/resources for a definition |
| `CapabilityOffer` | Service publisher | Caller authority view, revision, expiry | This caller may request evaluation of this contract within these limits |
| `Availability` | Capacity controller | Short-lived observation | Whether evaluation/execution capacity is presently available |
| `TaskAuthorization` | Receiver authorization resolver, private | One request digest and caller | Which actions/resources/disclosures and budgets this task may use |

A public offer MUST NOT expose executor IDs, tool IDs, model credentials, or filesystem locations. A service can offer a contract through approved delegation without having a local binding. Conversely, an installed binding is not automatically published to all callers. A caller's catalog is the complete set of active offers visible to that authority context, not a machine inventory.

An offer pins a definition reference, declares public effect terms, safe numeric budget minima, execution limits, and expiry. Published typed input and resource requirements belong in the capability definition. The provider checks private resource scopes and offer preconditions during its own admission. Catalog and single-offer responses omit those policy details. Offer effects must be a subset of the definition's ceiling. Offers cannot weaken required postconditions. Availability is not an offer, reservation, or permission; `busy` is not `unsupported`. Authorization can change after discovery and MUST be rechecked at admission and before each consequential action.

The target offer binds a public processing guarantee to the offer revision. Two offers may reference the same outcome contract and promise different processing terms. The provisioned downstream relationship pins private recursion terms to the exact peer offer, including the verification margin, lifetime fan-out, and any required subtree cap. See [target offer contract](multi-peer-delegation.md#target-offer-contract) and [recursive execution](multi-peer-delegation.md#target-recursive-execution).

`catalog_view` is an opaque receiver-issued identifier for the requesting principal's effective discovery policy. It must change when that policy changes, even if two views happen to list identical offers. It is not a bearer credential. The caller-scoped catalog has one stable revision across pages; a cursor pins that view and revision. If paging cannot continue consistently, return `409 catalog_changed`; never merge pages from different revisions. A missing offer means `not_claimed` only after a complete fresh enumeration or authoritative per-contract lookup, not after one page or a failed request.

The receiver resolves `TaskAuthorization` from its authenticated local principal, the selected offer, and current private policy. The request may supply supported task limits. LASA uses the same consumer protocol when it selects a downstream offer and the downstream receiver independently applies its own authorization.

## Concrete examples

[Design review definition](examples/capability-review.json) accepts supplied design text and review criteria and returns findings plus coverage evidence. [Task attempt definition](examples/capability-attempt.json) accepts an objective and explicit requirements and returns `fulfilled` or `unable` with evidence. `unable` is a valid outcome of an attempt contract, but it cannot satisfy a parent requirement for an actual review.

[Review offer](examples/offer.json) publishes a requestable outcome. [Private binding](examples/binding.json) selects an executor. [Availability](examples/availability.json) reports capacity. [Task authorization](examples/authorization.json) demonstrates receiver-owned execution permission. These are deliberately different artifacts.

Do not inflate the catalog with every tool, model, prompt template, or implementation branch. Publish a new capability only when callers need materially distinct inputs, outcomes, preconditions, effects, or verification. Common internal operations remain private. Deprecation withdraws future offers; it never mutates the historical definition pinned by an accepted task.
