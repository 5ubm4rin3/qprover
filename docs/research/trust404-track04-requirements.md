# TRUST404 Track 04 public requirements and compatibility boundary

Research snapshot: 2026-09-14 KST

## Verified public requirements

The [official Track 04 page](https://trust404.co.kr/en/tracks#track-04)
describes the input as a Solidity target, invariant set, and execution manifest.
The required loop derives attack candidates, generates a runnable exploit PoC,
executes it, and continues searching when the PoC does not violate an invariant.
One run must return the PoC and explain which invariant was violated and how.

The public judging priorities are:

1. the PoC executes and actually violates a supplied invariant;
2. identical conditions reproduce the result deterministically;
3. vulnerable targets yield valid PoCs without unsound PoCs on sound targets;
4. the system derives paths autonomously rather than replaying a known exploit;
5. the approach generalizes to unpublished targets and returns a minimal,
   reproducible PoC.

The page says the public targets, invariants, manifest, and detailed scoring
materials are distributed through the participant Discord. Unpublished targets
are used during judging.

The [submission page](https://trust404.co.kr/en/submit) requires a pitch deck in
PDF, a demo video no longer than five minutes that shows the build actually
running, and a public GitHub or GitLab repository with README run instructions.
The deadline is 2026-09-20 at 23:59 KST.

The [official rules](https://trust404.co.kr/en/rules) require the repository to
be public at submission, require disclosure of material AI-generated work,
require license compliance, and prohibit attacks outside organizer-provided or
explicitly approved environments. QProver's local-only execution policy is a
strict project safety boundary; the public Track 04 text itself does not state
that this track's grader is offline.

## Publicly unavailable material

No public-web copy was found for any of the following:

- Track 04 sample targets;
- invariant schema;
- execution-manifest schema;
- starter repository or runner command;
- result schema or scorer implementation;
- exact Track 04 scoring formula;
- a Track 04 submission example.

The official page contains no Solidity, JSON/YAML, archive, GitHub, GitLab, or
download link. The site map contains only informational pages. Searches of
GitHub, GitLab, public Drive/Docs, Notion, and indexed Discord content found no
organizer package. The Discord server is not publicly readable, and the
submission form requires an authenticated Google session because it accepts
file uploads.

Consequently, QProver must not invent an organizer schema or claim exact scorer
compatibility. That claim remains gated on lawful access to the participant
package.

## Architectural consequence: invariant violation and economics are distinct

The public track definition makes an executed supplied-invariant violation the
decisive event. Its example includes arbitrary total-supply inflation, which
need not produce a directly measured attacker gain and protocol balance loss.
The QProver development contract likewise requests profit/loss evidence only
when applicable.

The original QProver model required both:

```text
attacker_delta > 0 and protocol_delta < 0
```

before it called a false invariant a violation. That was too narrow. The final
model must keep two explicit evidence dimensions:

- `executed_invariant_violation`: a supplied, manifest-bound invariant evaluated
  false during controlled EVM execution;
- `economic_impact`: an additional manifest-bound qualification when the target
  declares profit/loss semantics.

This change does not weaken the ground-truth requirement. Static leads,
unevaluated expressions, failed or mismatched replays, and invented invariants
remain unconfirmed. Economic fixtures retain their stricter gain/loss gate.

## Current compatibility assessment

| Public contract | QProver internal model | Status |
| --- | --- | --- |
| Solidity target | Exact project-relative source closure and compiler evidence | Strong fit |
| Invariant set | Integer/boolean observations and a safe expression language | Partial; organizer form unknown |
| Execution manifest | Actors, funding, deployments, actions, domains, observations | Partial; organizer form unknown |
| Executed supplied-invariant violation | Controlled Anvil execution and Foundry replay | Strong after invariant-only policy support |
| Runnable PoC and explanation | Generated Foundry PoC and proof certificate | Strong superset |
| Deterministic minimal PoC | Execution-backed minimization and three private cold replays | Strong fit |
| Exact runner/result/scorer format | No public schema available | Unverified; adapter blocked |

Likely adapter gaps, which remain hypotheses until the real package is read:

- the organizer may separate setup transactions from searched actions;
- chain parameters may be manifest-controlled rather than fixed locally;
- action vocabularies and argument domains may need ABI/source derivation;
- invariant oracles may be Solidity callbacks rather than scalar expressions;
- the external runner may own budgets instead of the manifest.

## Fail-closed adapter plan

Once the official package is available, add a boundary adapter rather than
changing search internals:

```text
qprover trust404 run \
  --target TARGET \
  --invariants INVARIANTS \
  --environment MANIFEST \
  --out OUTPUT
```

The adapter will preserve and hash the exact input bytes, validate the official
schemas, translate only supported semantics into QProver's normalized scenario,
and emit the official result plus QProver's richer evidence bundle. If the
organizer supplies a Solidity/grader invariant callback, QProver should add an
invariant-oracle abstraction instead of performing a lossy translation.

Conformance requires golden tests against every official sample, execution under
the official runner, vulnerable/sound cases, deterministic replay, path and
schema rejection tests, and exact scorer acceptance. Unsupported semantics must
return `NOT_CONFIRMED`; they must never be guessed.

## External blockers

- Participant Discord access is required for the schemas, samples, and scoring
  details.
- An authenticated Google session is required to inspect and submit the file
  upload form.

Neither blocker prevents building, benchmarking, documenting, publishing, or
releasing QProver's local evidence pipeline.
