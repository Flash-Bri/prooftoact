# Prior-art and naming review

Initial orientation: 2026-07-29. Expanded primary-source review: 2026-07-31.
This is a bounded engineering and claims review, not an exhaustive literature,
patent, common-law, or trademark search and not legal advice.

## Release-blocking naming finding

The public GitHub repository
[`bigg-kay/TideProof`](https://github.com/bigg-kay/TideProof) predates this
repository. It describes seafood-freshness and sustainable-fishing
verification using GPS catch data, species identification, and cold-chain
timestamps. The name is identical case-insensitively and the neighboring
ocean, software, verification, and provenance themes create a material
confusion risk.

GitHub's repository API reported on 2026-08-01 that `bigg-kay/TideProof` was
public and created on 2026-03-20. The same API reported the current public
`Flash-Bri/tideproof` repository as created on 2026-07-30. These timestamps
support the limited predating statement; they do not establish first use in
commerce, ownership, registrability, or legal priority.

That repository is not proof of trademark ownership or infringement. It is,
however, enough to block final branding, video recording, and submission until
the entrant makes and records a rename/clearance decision. Registering
`tideproof.net`, finding no exact npm package, or finding a parked `.com` does
not clear the name. Any candidate name still requires exact and confusingly
similar searches through the USPTO, WIPO, EUIPO, relevant business registries,
package/app stores, domains, and common-law usage.

Two earlier working-name findings remain relevant:

- [`Highwater.ai`](https://highwater.ai) is already used by an unrelated
  AI-driven investment brand. “Highwater Drill” remains only the synthetic
  scenario label.
- The earlier document's exact “Blackbox Recorder”/MCP description was not
  reproduced. The closest reviewed project,
  [`Agent-Blackbox`](https://github.com/TaewoooPark/Agent-Blackbox), documents
  event replay, handoff, and context memory, but its reviewed README did not
  establish an MCP interface. Tideproof must not repeat the unsupported MCP
  comparison.

## Primary neighboring work

The individual mechanisms are established prior art:

- Lewis et al., [“Retrieval-Augmented Generation for Knowledge-Intensive NLP
  Tasks”](https://proceedings.neurips.cc/paper/2020/hash/6b493230205f780e1bc26945df7481e5-Abstract.html),
  NeurIPS 2020: dense retrieval plus generation; retrieval is not
  authorization.
- Park et al., [“Generative Agents: Interactive Simulacra of Human
  Behavior”](https://arxiv.org/abs/2304.03442): durable experience records,
  retrieval, reflection, and planning.
- Packer et al., [“MemGPT: Towards LLMs as Operating
  Systems”](https://arxiv.org/abs/2310.08560): hierarchical and long-term agent
  memory.
- Rasmussen et al., [“Zep: A Temporal Knowledge Graph Architecture for Agent
  Memory”](https://arxiv.org/abs/2501.13956) and
  [Graphiti](https://github.com/getzep/graphiti): temporal facts, source
  episodes, provenance, and invalidation. This is the closest reviewed
  neighbor on changing factual state.
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
  and the MCP reference
  [Knowledge Graph Memory Server](https://github.com/modelcontextprotocol/servers/tree/main/src/memory):
  checkpoints, failure recovery, time travel, thread/cross-thread memory, and
  persistent MCP-exposed memory.
- [W3C PROV-DM](https://www.w3.org/TR/prov-dm/): entities, activities,
  agents, derivation, invalidation, responsibility, and provenance of
  provenance. Provenance supports trust judgments; it does not itself confer
  authority.
- Snodgrass and Ahn,
  [“A taxonomy of time databases”](https://doi.org/10.1145/318898.318921),
  SIGMOD 1985: foundational valid-time and transaction-time concepts.
- Gray and Cheriton,
  [“Leases”](https://doi.org/10.1145/74850.74870), SOSP 1989, and Burrows,
  [“The Chubby Lock Service”](https://www.usenix.org/conference/osdi-06/chubby-lock-service-loosely-coupled-distributed-systems),
  OSDI 2006: leases, distributed locks, sequencers, and stale-holder rejection.
- AWS Builders' Library,
  [“Making retries safe with idempotent APIs”](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/):
  caller request IDs, atomic token/mutation storage, exact replay responses,
  late arrivals, and rejection when one token is reused with changed
  parameters.
- CockroachDB's official documentation for
  [Distributed Vector Indexes](https://www.cockroachlabs.com/docs/v26.2/vector-indexes),
  [`SERIALIZABLE` isolation](https://www.cockroachlabs.com/docs/v26.2/demo-serializable),
  and [CockroachDB Cloud Managed MCP](https://www.cockroachlabs.com/docs/cockroachcloud/connect-to-the-cockroachdb-cloud-mcp-server):
  ANN retrieval with exact prefix filters, serializable transaction behavior,
  and provider MCP access are platform primitives, not Tideproof inventions.
- The [Model Context Protocol](https://modelcontextprotocol.io/introduction) is
  an open standard for connecting AI applications to data, tools, and
  workflows. MCP alone does not confer Tideproof's authority semantics.

## Closest-work comparison

RAG, Generative Agents, and MemGPT optimize retrieval, reflection, context
capacity, and continuity. Zep/Graphiti is the closest reviewed work on
temporal validity, provenance, and fact invalidation. LangGraph and the MCP
memory server are strong precedent for checkpoint recovery and persistent
cross-session memory. Leases, Chubby sequencers, and AWS idempotency are direct
precedent for scarce authority, fencing, exact duplicate replay, changed-input
rejection, and reconciliation. CockroachDB DVI, serializable transactions, and
Managed MCP are provider primitives.

Tideproof's defensible contest differentiation is the demonstrated
composition and judge-visible invariant, not any individual mechanism:

> Remembered is not the same as admissible, and admissible is not the same as
> authorized.

The synthetic demonstration separately tests attributable and current
evidence, transactional authority spending with durable receipts and fencing,
and successor context recovery without operational capability transfer.

## Safe public originality boundary

Tideproof does **not** claim to invent RAG, provenance, temporal memory,
conflict handling, leases, fencing, idempotency, replay protection, durable
checkpoints, MCP, Distributed Vector Indexing, serializable transactions, or
exactly-once effects. Avoid “first,” “unique,” “novel,” and “only” unless the
sentence is explicitly scoped to this synthetic demonstration and supported
by accepted evidence.

The current DVI and full-admissibility receipts are separate historical
proofs. Until a fresh integrated plan/exclusion receipt is accepted, public
copy must say so and must not claim that the historical named vector index
directly ranks the output of the full admissibility predicate.

## Final review requirements

Before final branding or submission:

1. record the entrant's name/rename decision and the search evidence used;
2. rerun exact and confusingly similar name searches close to release;
3. preserve this bibliography and closest-work comparison with the final
   claim review;
4. bind every originality sentence to the exact release source and evidence;
5. disclose reused libraries and all pre-existing inputs; and
6. obtain qualified legal review if the entrant wants actual clearance rather
   than this bounded engineering stop gate.
