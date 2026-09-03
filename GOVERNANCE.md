# Governance

This document is the contract behind every rule SQLens ships. It exists because a
linter's real cost is not the code it finds — it is the day it starts failing a
pipeline that was green yesterday, for a reason nobody agreed to.

## What is public API from 1.0

Four things are public API, and renaming any of them is a breaking change:

- **Rule ids** — `PG.L2.CONCURRENTLY` and its kind
- **Message prefixes** — `sqlens.lint`, `sqlens.security`, …
- **Exit codes** — the four values and their meanings
- **The baseline format** — the file a repository commits

A rule is never deleted. When one is superseded it becomes **deprecated**: it stops
producing findings and says so, with a notice naming what replaced it. A
suppression that names a deprecated rule keeps working. Deleting a rule id would
turn a documented suppression into an error in someone's pipeline, months after
anyone remembers the id.

## How a new rule reaches you

New rules arrive as **`preview`** and are opt-in. They move into a level's defaults
only in a **major** release.

That constraint is not caution for its own sake. A linter that adds a default rule
in a minor breaks builds on `composer update` — for a change nobody asked for, in a
release people install precisely because it should be safe. The alternative is
worse than a slow rollout: teams pin the version, stop updating, and stop getting
security fixes.

**One exception, deliberately.** A **security severity may be raised in a minor**,
with a callout in the changelog. If a finding turns out to be worse than first
judged, waiting for a major to say so protects the release schedule at the expense
of the user.

That exception is enforced, not trusted: a release gate diffs the rule contract
against the last released one and refuses a raised severity whose changelog callout
is missing — along with any lowered severity, any deleted rule id, and any change it
cannot classify. See "Rule governance" in [CONTRIBUTING.md](CONTRIBUTING.md).

### Stability tiers

| Tier | What it promises |
| --- | --- |
| `stable` | The rule's id, message prefix and meaning are covered by the policy above. |
| `preview` | The rule works and is opt-in. Its id and message may still change in a minor. |
| `experimental` | Available to try. It may change or disappear in any release. |

The tier is visible in the output, not only in the docs — a preview finding is
marked where you read it.

### What makes a preview rule ready

A tier is a promise, so moving one is a decision with criteria rather than a
judgment call. **All five must hold** before a rule leaves `preview`:

1. **A measured false-positive rate**, below a stated threshold, against a corpus
   of migrations people actually wrote. Not a synthetic corpus: a rule that guesses
   is guessing about somebody's real naming, and a fixture we authored agrees with
   us by construction.
2. **A bad/good fixture pair for every driver the rule judges.** One driver
   covered is a rule proved on half its surface.
3. **Evidence on file** — official documentation, or a documented incident. The
   same bar a proposal has to clear, re-checked because documentation moves.
4. **A written false-positive assessment**: what the rule cannot see, and what it
   will therefore report wrongly. Every rule has such a case; a rule whose author
   cannot name one has not looked.
5. **No open false-positive report against it.**

Two things this list deliberately does **not** say:

- **Nothing here is about age.** A rule does not graduate by surviving releases.
  Time in `preview` is evidence of nothing, and treating it as evidence is how a
  rule nobody exercised becomes a default.
- **Not every non-stable rule is a candidate.** A rule can be `preview` or
  `experimental` because of what it *is* rather than how far along it is — a
  verdict that depends on when you ask it will never satisfy criterion 1, however
  mature the code. Those are permanent, and the register that names each
  non-stable rule says which kind each one is, so a promotion round does not have
  to re-derive it per rule.

Promotion happens **at a major**, and never one rule at a time in a minor: see the
policy above.

## Proposing a rule

A rule proposal needs three things, and the requirement is a fence against
bikeshedding rather than bureaucracy:

1. **Evidence** — official documentation, or a documented incident. "This seems
   risky" is where a false-positive machine starts.
2. **A false-positive assessment** — where does this rule fire when it should not?
   A rule with no answer is not ready.
3. **A proposed level and severity**, with reasoning.

A false-positive report needs a reproducible snippet. Both live in the issue
templates.

## What SQLens never does

- **No telemetry.** Not opt-out, not anonymous, not "just counts". A tool that
  reads your schema has to be trustworthy about what leaves your machine, and the
  only version of that promise worth making is the absolute one.
- **No implicit network access.** Nothing fetches anything during a normal run.
  Refreshing advisory data is a separate, explicit command you choose to run.
- **No database writes.** Not a table, not a row, not a temporary object. The debt
  ledger is a file in your repository, on purpose.
- **No locks of its own.** The tool must be safe to run against a production
  database that is already under load.

## Contributions: DCO, not a CLA

Contributions are accepted under the **Developer Certificate of Origin**: you sign
off that you have the right to contribute what you wrote. There is no copyright
assignment and no contributor license agreement.

That is a decision with a consequence, and it is better made calmly now than in
frustration later. Without assignment, the project **cannot** relicense itself away
from MIT. Someone may run SQLens inside a commercial product, or fork it, and that
is allowed — permanently, by construction. A CLA would keep a relicensing option
open, and the cost of that option is that every contributor has to sign a legal
document before their first patch.

## Extending SQLens

From 1.0 the rule contract is a stable extension API: a third-party package can
ship its own rules against it. The driver boundary works the same way — a new
engine attaches through the driver registry rather than by editing the core. See
`CONTRIBUTING.md`.
