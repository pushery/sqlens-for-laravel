# Contributing

Thanks for considering a contribution — issues and pull requests are both welcome.

## Reporting an issue

Use the GitHub issue templates (bug report / feature request). Include the package
version and a minimal reproduction, and never paste secrets or credentials.

## Pull requests

- Keep the public API stable, or call out the break explicitly.
- Add tests for any behavior change.
- Update `README.md` and the `CHANGELOG.md` `## [Unreleased]` section.
- Keep each commit focused.

## Where this file applies

If you are reading this on **docs.pushery.com** or in a checkout of the public package,
you are looking at a **generated mirror**. It carries the shipped tree only — `src/`,
`config/`, `lang/`, `resources/` and the documents beside them — and it is rewritten
from the development repository on every release. The branch model, the test suites and
the `just` recipes below describe that development repository; the directories they
name are not in the mirror, and a pull request opened against the mirror is overwritten
by the next release rather than merged.

**Issues are the right channel from the mirror**, and they are read. For a code
contribution, open an issue first and the maintainers will bring you into the
development repository — that way your work lands somewhere it survives.

## Branch model

*(In the development repository.)* Day-to-day work happens on `develop`, which is the
default branch — open your pull requests against it. Cut a topic branch from `develop`,
and it merges back into `develop` when it is ready.

`main` is release-only: it receives a merge from `develop` only when a version is
cut, immediately followed by the `vX.Y.Z` tag that drives the release. Nothing is
committed to `main` directly, so `main` always reflects the latest published
release. The push gate is local — the maintainers run the full quality gate on
their own machine before a release, and a pre-push hook refuses a `main` push (or a
version tag) that is not backed by a green run.

## Rule ids and message prefixes

Rule ids are public API from 1.0 on: they appear in output, in ignore lists, and in
documentation URLs, so they are named once and never renamed. A rename is a breaking
change, and a retired id is never recycled.

The scheme is `<AREA>.L<n>.<NAME>` for a leveled rule:

- **`AREA`** is one of `PG`, `MY`, `GEN`, `CAP` — PostgreSQL, MySQL, a driver-agnostic
  rule, or the capture layer that obtains the SQL in the first place.
- **`L<n>`** is the strictness level `L0`–`L9` the rule sits at for that area (the same
  rule can sit at different levels on different drivers).
- **`NAME`** is `UPPER_SNAKE_CASE`, starts with a letter, and is a stable, speaking name —
  never a meaningless running number. Prefer `INDEX_NOT_CONCURRENT` over `RULE_017`.

Examples: `PG.L2.INDEX_NOT_CONCURRENT`, `MY.L4.UTF8MB3`, `GEN.L5.FK_WITHOUT_INDEX`.

### Security rules carry no level — they name the question they ask

A security rule is weighed on the **severity** axis and ignores the level gate entirely, so
a level in its id names an axis it is not measured on. `SEC` is therefore absent from the
list above, and `SEC.L0.GRANT_PUBLIC` is **malformed** rather than merely old — the format
contract rejects it, so the convention cannot be broken by copying a neighboring file.

The shape is `SEC.<AREA>.<NAME>`, with four areas:

| Area | The question it asks | Typical subject |
|---|---|---|
| `SEC.CFG` | Is the **server** configured safely? | a setting, a GUC, a system variable |
| `SEC.AUTH` | How does somebody get **in**? | credentials, password hashes, host matching, `pg_hba.conf` |
| `SEC.PRIV` | What may they do **once in**? | grants, role attributes, ownership, connection separation |
| `SEC.RLS` | Does row-level security actually **bite**? | enablement, forcing, policies |

The area follows the **subject a rule reads**, not the topic its name evokes.
`SEC.CFG.LOCAL_INFILE_FILE_GRANT` judges a server variable although its name says GRANT,
and `SEC.PRIV.ROLE_BYPASSRLS` reads a role attribute although its name says RLS. Read as
"fixed by editing configuration" instead of "reads a server setting", the `CFG` boundary
would stop separating anything — plenty of `AUTH` and `PRIV` rules are also fixed by
editing a file.

Examples: `SEC.PRIV.GRANT_PUBLIC`, `SEC.AUTH.HBA_TRUST`, `SEC.CFG.TLS_DISABLED`.

**Reserved:** two families sit outside both shapes, because neither describes a strictness
appetite nor asks one of those four questions.

- `SEC.SKIPPED.*` is reserved for the security suite's degradation findings — a check that
  could not run (missing privilege, unreachable server) is reported as an `undetermined`
  `SEC.SKIPPED.<REASON>` finding, never swallowed as a pass.
- `CAP.PRESCAN.*` is reserved for what the static pre-scan found in a migration before
  anything ran. A pre-scan hit is why a migration was never captured, not a judgment
  about the SQL it would have produced, so it has no level to sit at.

The format is enforced in code (`Pushery\SQLens\Rules\RuleIdFormat`) and asserted over the
whole rule registry, so a malformed id cannot reach the catalog. The documentation URL
pattern that pairs with each id is defined separately.

## The driver boundary

SQLens ships one package with two strictly separated driver namespaces:
`Pushery\SQLens\Drivers\Pgsql` and `Pushery\SQLens\Drivers\Mysql`. Neither may
reference the other — not by import, and not by a fully qualified name written
inline. Everything else under `Pushery\SQLens\` is the neutral core, and it may
know only the `Driver` contract, never a concrete driver class.

**This rule is not negotiable, and it is worth knowing why.** It is the insurance
that splitting SQLens into a core plus two driver packages stays a mechanical move:
directories change place, namespaces do not, and nobody's imports break. The day
one driver reaches into the other, that stops being true — and the coupling that
costs it always looks small and reasonable on the day it is added. So there is no
allowance list and no suppression comment. If the rule is in the way, the design is
what needs to change.

Two arch tests enforce it, and both report the exact file and line:

- `tests/Unit/DriverIsolationArchTest.php` — neither driver namespace references
  the other, in either direction.
- `tests/Unit/CorePurityArchTest.php` — the core references no concrete driver AND
  carries no engine vocabulary (`pg_catalog`, `information_schema`,
  `CONCURRENTLY`, …) in a string literal. The second half matters on its own:
  a core that never imports a driver but embeds a catalog name is engine-specific
  anyway, and no import guard would notice.

The core rule is written INVERTED — everything except the two driver namespaces —
so a namespace added later is covered without anyone remembering to list it.

### Why it is one package, and what would change that

The insurance above is worth stating as a decision rather than leaving as a
tendency: **one package is the choice for 1.0, and splitting into a core plus two
driver packages stays available.** Taken 2026-07-22, and the reasoning matters more
than the verdict.

The measurement that would justify a split is *release coupling pain* — how often a
release was held back because of the other engine — and before a first release that
number has no history at all. Splitting on it would be a bet against our own plan.
The two engines are also built in parallel with shared plumbing and rules mirrored
across both, so the trigger the split exists for ("the engines' maturity diverges")
is not met by construction.

What makes waiting free is that the door stays two-way. Because the isolation above
holds, the move is mechanical whenever it is wanted; three repositories merged back
into one is the direction that is hard to undo, and consumers feel it.

The threshold was fixed **before** the measurement, so a later decision is made
rather than justified afterwards. All three must hold:

1. Over at least three consecutive minors, a release was demonstrably held back
   **twice or more** because of the other driver. A maturity gap alone is not
   release pain.
2. One driver below 60% `stable` rules while the other is above 85% — or the two
   drivers' false-positive rates more than a factor of two apart.
3. The move is still mechanical: the isolation tests above are green. If they are
   red, the problem is the isolation and not the topology, and the work goes there
   instead.

If 1 and 2 hold but 3 does not, fix the isolation first. If only 2 holds, one
package stays. Re-examined after the first three minors past 1.0, or at the first
major — whichever comes first — and at every major after that.

**If it is ever done, it is a monorepo with read-only subtree splits** (the shape
`symfony/symfony` publishes from), not three hand-maintained repositories. Three
development repositories is the overhead this decision avoids, and it risks
reintroducing the duplicated plumbing that ruled out a per-driver layout in the
first place.

Exactly four places may name a concrete driver, because something has to assemble
the parts: `DriverRegistry` (which maps a driver key to an implementation),
`CanonicalExtensionRegistry` (the one sanctioned bridge from canonicalization to a
driver's canonicalization), `DriverCaptorFactory` (the capture bridge that
assembles a connection's captor from its canonicalization and binding formatter),
and `SQLensServiceProvider` (the composition root itself, where each driver key is
mapped to its catalog readers). That list is pinned by the test, so a fifth one
fails the build.

### Where driver-specific code goes

Anything that names a catalog, a system view, engine-specific syntax, or a
version-gated behavior belongs inside the driver namespace for that engine. If a
rule needs the same shape on both engines, the SHAPE goes in the core and each
driver supplies its own specifics through the `Driver` contract.

### Adding a driver

Third-party drivers attach through the registry rather than by editing the core:

```php
use Pushery\SQLens\Drivers\DriverRegistry;

public function boot(DriverRegistry $registry): void
{
    $registry->extend('acme', fn (): Driver => new AcmeDriver);
}
```

`extend()` takes NEW keys only. It refuses a key that is already registered — a
silently overwritten driver is the kind of bug nobody notices — and it refuses the
reserved keys `mariadb`, `sqlite` and `sqlsrv`. Those are deliberate non-goals that
route to a named unsupported result, and letting a custom driver claim them would
quietly undo that decision: MySQL rules would run against a MariaDB, producing
advice that is confident, specific and wrong.

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of
Origin](https://developercertificate.org/) — a lightweight statement that you have
the right to contribute what you wrote. There is no copyright assignment and no
contributor license agreement, and that is a deliberate choice: without a CLA there
is no single party who could relicense the project, so the MIT grant is structurally
permanent. "MIT today" only means "MIT tomorrow" if no one holds the right to change
it out from under everyone — the DCO is how that stays true, which is why the check
is not bureaucracy.

Sign off every commit:

```bash
git commit -s
```

That appends a `Signed-off-by:` line matching your git identity. If you forget, fix
the last commit with `git commit --amend -s`, or a whole branch with
`git rebase --signoff <base>`. A CI check and a local `commit-msg` hook both require
the sign-off, so a missing one is caught at commit time rather than in review — run
`just setup` once per clone to wire the hook.

**A squash merge needs more than the trailer surviving.** GitHub squashes server-side and
re-authors the result: the author becomes the identity of the GitHub account and the
committer becomes `GitHub <noreply@github.com>`. The check requires the `Signed-off-by`
line to match the author or the committer, so a sign-off written from a different
`git config user.email` matches neither — even though the trailer is still there,
verbatim, in the message. Doing everything right and still failing is the usual way
this is met.

A merge or rebase merge does not have that problem: the range the check walks is the
branch's original commits, which are still authored locally and still carry the matching
sign-off.

**So the squash button is switched off for this repository, and that is the decision rather
than a note about one.** `allow_squash_merge` is `false` here since 2026-09-09. The paragraph
above explains a failure that can only be met by choosing an option this repository has no use
for: the fleet's branch model merges, the DCO check's range is built for a merge commit, and a
squash produces a commit the repository's own gate then refuses. Leaving the button there and
writing "please do not press it" is the shape that gets pressed anyway, at the end of a long
day, by whoever did not read this far.

⚠️ **It is off HERE and nowhere else, deliberately.** Squash merging is not harmful in general
and the rest of the fleet keeps it; this is the one repository with a DCO gate, so it is the one
repository where that button produces a commit its own CI rejects.

The two heavier remedies stay unbuilt on purpose. Aligning `git config user.email` with the
GitHub account's commit address would fix it and would also rewrite the identity on every other
repository's future history. Teaching the check to accept the account address as a second
identity changes **whom a security check trusts**, which is a decision worth making
deliberately or not at all — and neither is needed once the option that triggers it is gone.

## Licensing policy

SQLens is MIT licensed, and every dependency it pulls in has to be compatible with
that. Every package in the resolved tree is held against a machine-readable license
policy — an SPDX allowlist, with an explicit denylist for copyleft and
source-available licenses, and the rule that an unknown or undeclared license fails
the build rather than passing quietly. The allowlist is the binding source of truth,
enforced identically by the local gate, the CI job, and the test suite, so a pull
request that adds a dependency outside it fails before a human has to catch it.

Copyleft libraries are never required — they are *suggested*. Where a copyleft
library genuinely adds value (for example `phpmyadmin/sql-parser`, GPL-2.0, for an
optional MySQL parser path), it goes into `suggest` and the application makes the
combination: installing it is the application's own decision, taken knowingly, and
this package's own tree stays under its published license. At runtime the capability
is detected, never assumed — via `Composer\InstalledVersions` and `class_exists()` on
the library's entry class — and when it is absent, the checks that would need it
report a named undetermined result instead of failing. A guard test pins all of this:
no denied license in `require` or `require-dev`, and the suggested parser present only
under `suggest`.

Shelling out to an external *binary* (such as `squawk`, `pgFormatter`, or `SQLFluff`)
is a different situation from linking a library: the binary runs as a separate
program, no derivative work arises, and its license does not constrain this
package's. Bundling such a binary inside the package would — so SQLens invokes
external tools where the user installed them and ships none of them.

Any data the package bundles is attributed in [NOTICE](NOTICE), which records the
source, license, and retrieval date of each data artifact. A data file with no such
entry fails the build.

## Provenance

The documentation, the rule explanations, the bad/good examples, and the test
fixtures are all written from scratch. Do not copy tables, wording, or example
migrations from another project's documentation — not from Squawk, not from the
PostgreSQL or MySQL manuals, not from a competing tool. Rephrase in your own words
and cite the source with a link instead. Test fixtures are synthetic: an invented
schema that isolates the behavior under test, never a snippet lifted from a real
codebase. This matters most once the rulesets grow, and it is enforced where it can
be — the fixture sweep rejects third-party origin markers, and bundled data must be
registered in `NOTICE` — but outside the checks named below, the prose relies on you.

Bundled data that states vendor behavior is held further, because it is the place
where copying is most tempting and hardest to spot afterwards. Every entry of the
online-DDL matrix has to cite the **versioned** manual page it was read from — a
host alone is not enough, since the same manual is served under several hosts and
in several releases, and the cheapest way for a fact to be quietly false is to be
true of another version. The cited anchor has to be one the page really has, the
retrieval date has to be a real day no earlier than the release it documents, and
every `notes` and `conditions[].text` has to be long enough to be an explanation
rather than a table cell. On top of that, a small list of phrasings distinctive of
the manual's *voice* — its recurring boilerplate, its table legend — is checked
against your prose.

**When that tripwire fires, reword the text.** It does not mean the fact is wrong
or that the entry has to go; it means the sentence reads like the manual's rather
than yours. Say the same thing in your own words and it passes. Do not delete the
phrase from the list, and do not lower a threshold to get to green — the list is
deliberately small and holds no free facts (`rebuilds the table`, `in place`,
`concurrent DML` and their like are ours to use), so a hit is worth a second look
rather than a workaround.

## Proposing a rule

A rule enters SQLens with evidence, not on taste. Open a **Rule proposal** issue
(the form walks you through the required fields) and bring: a link to official
documentation or a documented incident that establishes the behavior, a
false-positive assessment, and a proposed level, category, severity, and downtime
class — plus a bad/good example you wrote yourself.

Before you do, read [GOVERNANCE.md](GOVERNANCE.md). It is the contract behind the
rules: what a proposal needs, why a new rule arrives as `preview` rather than
straight into a level's defaults, when it graduates, and what counts as public API
from 1.0 on (rule ids, message prefixes, exit codes, the baseline format).

## Rule governance

[GOVERNANCE.md](GOVERNANCE.md) states what the rule set promises between releases.
`just governance` (part of `just all`, and `composer governance:check` on its own)
checks it instead of trusting it — it diffs the rule contract this tree carries
against the contract of the last release and classifies every difference:

| Class | What it is | What the gate does |
| --- | --- | --- |
| **tightened** | a severity went up, or an unrated rule gained a rating | allowed **with** a changelog callout, red without one |
| **loosened** | a severity went down, or a rated rule lost its rating | red — withdrawing a promise is a major-version topic |
| **added** | a rule id the last release did not have | allowed, and reported so it is never invisible |
| **removed** | a rule id the last release had | red — rules are deprecated, never deleted |
| **unclassified** | a change with no class, currently a category change | red — the gate refuses to invent a verdict |

The two sides of the diff are:

- **now** — `resources/data/rule-registry.json`, the generated catalog. It is
  regenerated in the same change that touches a rule (`RuleRegistryExportTest`
  fails otherwise), so it always describes this tree.
- **the last release** — `.github/governance/rule-contracts.json`, a snapshot with
  a different lifecycle: it changes **only at a release**. That difference is the
  whole mechanism. A gate that diffed the registry against the code would compare
  a file to itself and could never go red.

### Announcing a tightening

A severity may be raised in a minor — a security risk does not wait for the next
major — but only where a reader of the release notes will find it. Add an entry
under `### Security` inside `## [Unreleased]` in `CHANGELOG.md` that **names the
rule id** and says what a consumer's run will now do differently:

```markdown
## [Unreleased]

### Security

- **SEC.PRIV.LITERAL is now `high`.** A hardcoded credential in a migration blocks a
  run whose `security.min_severity` is `high`, where it previously needed `medium`.
```

Only the `### Security` rubric of the `[Unreleased]` section counts. A mention in
`### Fixed` or in an already-released section does not: otherwise a rule that got a
typo fix in the same release would silently satisfy the requirement for a severity
change nobody wrote about.

### Updating the snapshot

Regenerating the snapshot is a **release** act, and it is the one thing that must
never be done to make this gate green — it erases the promise the gate was
protecting. At the release, with the version being tagged:

```bash
SQLENS_WRITE_GOVERNANCE_SNAPSHOT=1.2.0 php .github/governance/check-rule-governance.php
```

Commit the result with the release. From then on it is what the next diff measures
against.

## Fixture pairs

Every rule is held by a **pair**: a migration that must make it fire and one that must
keep it silent. Both live in one directory named after the rule id, lowercased with dots
turned into dashes — the same slug the rule's documentation URL uses, so one id has one
slug everywhere:

```text
tests/Postgres/Fixtures/pg-l2-concurrently/
    bad.php          the migration the rule must flag
    good.php         the same intent, done safely — it must produce NO finding
    expected.json    exactly what bad.php produces
```

The `good.php` half is the one that is tempting to skip and the one that earns the rule
its trust: a good fixture that fires is how a false positive announces itself. A pair
missing either half fails the suite.

`expected.json` is validated, not trusted. Its shape:

```json
{
    "schema_version": 1,
    "rule_id": "PG.L2.CONCURRENTLY",
    "provenance": "synthetic",
    "run": {
        "server_version": "18.0",
        "tool_versions": {}
    },
    "overall_status": "fail",
    "findings": [
        {
            "rule_id": "PG.L2.CONCURRENTLY",
            "status": "fail",
            "level": 2,
            "category": "safety",
            "confidence": "deterministic",
            "downtime_class": "blocking"
        }
    ]
}
```

Four parts of that are easy to underestimate:

- **`schema_version` is mandatory, and an unknown one is an error.** Fixtures outlive the
  code that reads them. A file written for a later format must stop the run rather than
  be read under the older one, where a field the reader does not know simply vanishes and
  the fixture quietly pins less than its author wrote.
- **`confidence` is mandatory on every finding.** A heuristic rule cannot get a fixture
  accepted without declaring its verdict a heuristic — the honesty rule is enforced by the
  schema, not by searching a message for a caveat.
- **The run parameters belong to the expectation.** Both the pinned server version and the
  tool versions: without the latter, the same file is equally "correct" under two
  different versions of an external tool, and a fixture that changed meaning with a tool
  upgrade would still pass.
- **`provenance` must be `synthetic`.** Fixtures are written for this repository. Nothing
  is copied from Squawk, from the PostgreSQL documentation, or from any other project, and
  a test checks that every fixture file says so.

Optional fields (`severity`, `downtime_class`, `undetermined_reason`) are omitted when
they do not apply rather than written as `null` — absence means "this rule makes no claim
here", which is not the same as a claim of nothing. Entries are sorted by rule id, so a
diff of a regenerated file shows a changed expectation and never a reshuffle.

### Regenerating an expectation

When a rule's behavior legitimately changes, do not hand-edit `expected.json` — regenerate
it from the actual run and review the diff:

```bash
just fixtures-update
```

This rewrites every `expected.json` through the **same serializer** the check uses, so the
result is deterministic and the diff shows only what actually changed. It **never commits**:
the git diff is yours to read, and it is part of the review, not a rubber stamp — a diff you
did not expect is a rule whose behavior changed in a way you did not mean.

The mode is **locked out of the quality gate.** It runs only without code coverage; set
`SQLENS_UPDATE_FIXTURES=1` during a coverage run and the suite aborts with a named reason.
That is not ceremony: a mode that fits the expectation to reality must never run in the pass
that *checks* reality, or a rule bug would regenerate its own expectation to green and every
fixture would certify only that the bug agrees with itself.

## Quality bar

This package holds itself to a strict quality bar — Laravel Pint, Larastan at `max`,
Rector, and Pest with 100% line and type coverage, plus mutation testing, a
real-browser end-to-end suite, and cross-engine tests against real PostgreSQL and
MySQL 8.4 (the engines it runs on in production). The maintainers run the full gate
locally before every release, so a pull request that keeps the public API stable and
ships tests for its change is easy to accept.
