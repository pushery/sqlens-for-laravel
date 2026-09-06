---
name: sqlens-for-laravel
description: >
  Install, configure, and apply the SQLens for Laravel package in a Laravel
  application.
license: MIT
metadata:
  author: pushery
---

# SQLens for Laravel

Use this skill when a Laravel application installs or integrates the
`pushery/sqlens-for-laravel` package. Laravel Boost surfaces it inside
consuming applications, so keep it focused on adoption — never on package
internals.

## Primary Goal

Apply the package's public API in the smallest correct way for the consuming
application.

## Workflow

### 1. Install

```bash
composer require pushery/sqlens-for-laravel
```

The service provider is registered automatically through package discovery.

### 2. Configure

Publish everything at once, or only the configuration file:

```bash
php artisan vendor:publish --tag="sqlens"
php artisan vendor:publish --tag="sqlens-config"
```

`config/sqlens.php` documents every option inline. The ones a new application usually
sets first: `connection` (the database connection SQLens targets; `null` uses the
application's default), `level` (the cumulative strictness), `profile` (the active
environment profile), `baseline.path` (where an adopted baseline is written), and
`strict_tools` / `strict_undetermined` (whether a missing tool or an undecided check
fails the run).

Shadow mode (the truth mode that runs migrations for real against a disposable
database) is opt-in and needs more than read-only access — a dedicated `CREATEDB`
role, kept separate from your runtime and migration roles. It stays off unless you
configure `capture.shadow` and pass the production guard. See the
[shadow-mode guide](https://docs.pushery.com/sqlens-for-laravel/shadow-mode/)
before enabling it.

### 3. Check the environment

```bash
php artisan sqlens:doctor
```

`sqlens:doctor` reports the versions SQLens reasons about — PHP, Laravel, the
package, the OS — and, per configured connection, the driver and the real server
version. It is read-only: it opens no write and takes no lock. A connection it
cannot reach is reported as `undetermined` with a named reason, never a silent
"ok". Run it first to confirm the tool sees the database you expect.

### 4. Lint the pending migrations

```bash
php artisan sqlens:lint
```

`sqlens:lint` resolves the target connection's pending migrations, captures each
one's SQL without executing it — the default, do-no-harm `--pretend` mode — and
reports a three-valued result (`pass` / `fail` / `undetermined`) with a
reproducibility header naming the mode and the real server version. A check that
could not run is reported as `undetermined` with a named reason, never a silent
pass.

Scope the run when you need to:

```bash
php artisan sqlens:lint --connection=pgsql --path=database/migrations --level=4 --category=safety,performance
```

- `--connection` targets a specific connection (defaults to `sqlens.connection`,
  then the application default).
- `--path` (repeatable) limits the migrations scanned (defaults to the
  application's registered migration paths).
- `--file=<migration>` (repeatable) lints the migrations you name and nothing
  else, without a database connection — the fast path for a pre-commit hook or an
  editor save on the file that just changed. Name every staged migration in one
  call and the hook pays one process start instead of one per file. It runs the
  same rules and suppression as a full run, so a baseline entry or a
  `#[SqlensIgnore]` still applies. Each file must sit inside a configured
  migration path; it is pretend-only (not combinable with `--shadow`).
- `--profile=local|ci|predeploy` presets an environment's strictness settings in one
  named choice. A profile is a partial override of the configuration; anything it
  does not name keeps its configured value. `local` overrides nothing (the shipped
  defaults are already lenient), `ci` raises the level and arms the strict flags, and
  `predeploy` is reserved for the deploy suite. The active profile comes from
  `--profile`, then `SQLENS_PROFILE`, then `sqlens.profile` — never from `APP_ENV`,
  so a pipeline states its gate rather than inheriting one. An unknown profile is a
  configuration error, never a quiet fall back.
- `--level=0..9` sets the cumulative strictness (defaults to `sqlens.level`);
  level `n` runs every rule at level `<= n`. Security and privacy rules ignore it —
  a level-0 run can still report a critical.
- `--min-severity=info|low|medium|high|critical|none` sets the security severity
  floor for the run (defaults to the profile's, then `sqlens.security.min_severity`,
  which ships as `high`). `none` means report without ever blocking; it silences
  nothing, it only stops those findings deciding the exit code. An unknown value is
  a configuration error, never a quiet fall back to a floor nobody chose.
- `--category` (repeatable and comma-separable) scopes the run to one or more of
  `safety`, `performance`, `idiom`, `convention`, `security`, `privacy` (defaults to
  `sqlens.categories`; empty means all). A scope that matches no rule is reported as
  `undetermined`, never a silent pass.
- `--format=console|json|github` chooses the output (defaults to
  `sqlens.reporting.default_format`); `--format=github` emits pull-request
  annotations for CI. `--output=<file>` writes the report to a file.
- `--strict-tools` / `--no-strict-tools` decide what a missing optional external
  tool means (defaults to `sqlens.strict_tools`): strict makes it an error so a CI
  run cannot pass with fewer rules than intended, non-strict reports it as a named
  `undetermined` and keeps going. Set `--strict-tools` in CI.
- `--shadow` runs the migrations for real against a throwaway database SQLens
  provisions and drops itself, instead of collecting their SQL without executing it.
  Reach for it when a pretend run reports an `undetermined` it cannot resolve — a
  result-dependent migration, or an error that only happens on real data. It needs
  the setup in the [shadow-mode guide](https://docs.pushery.com/sqlens-for-laravel/shadow-mode/) and passes a production guard that refuses a
  disallowed environment, a production-looking connection, and an unconfirmed run.
  `--force` supplies the confirmation for a pipeline; it waives nothing else.
- `--roundtrip` (shadow only) replays `up` → `down` → `up` in that throwaway database
  and reports whether `down()` is a real inverse — the check that catches a rollback
  which cannot run or does not restore. It executes `down()` for real, so it is
  refused without `--shadow`, refused against a `--connection`, and refused with
  `--file`. A deliberately irreversible migration is annotated, not left to fail.

The exit code is the gate contract: `0` clean, `1` findings above the gate, `2`
misconfiguration — including an unsupported engine, since SQLens targets
PostgreSQL 18+ and MySQL 8.4+ and reports any other connection rather than passing
it silently — and `3` an undetermined check under strict mode. Wire that exit code
into CI to fail a build on an unsafe migration.

### 5. Audit the live schema

`sqlens:lint` reads the migrations you are about to run. `sqlens:audit` reads the
database you already have — its tables, indexes, keys and server settings — and
judges what is there rather than what is arriving.

```bash
php artisan sqlens:audit --connection=pgsql --level=5
```

- **The connection is a statement, not a guess.** With more than one configured
  connection the run refuses rather than picking whichever is default, because a
  report about the wrong database is indistinguishable from a report about the right
  one. Name it with `--connection`, or set `sqlens.connection`.
- **A connection that offers a choice of read hosts needs `--host`.** Laravel picks
  one at random at connect time; an audit that accepted that would describe a
  different server on different runs. A host the connection does not offer is an
  error, not a fallback.
- Same options as the lint suite where they mean the same thing: `--connection`,
  `--profile`, `--level`, `--category`, `--format`, `--output`.
- **`--strict` is an audit option only.** It treats an undetermined result as a failure.
  The lint suite has no `--strict`; its nearest equivalent is `--strict-tools`, which is
  a different question — what to do about a missing external tool, not what to do about a
  check that could not conclude.

The report header states which instance answered, its role, the server version, the
profile, and everything the reading could not cover — read it before the findings.

#### On a replica, some questions are withheld

If the addressed instance is not on the write path, rules whose verdict is about the
instance — server settings, timeouts — report `undetermined` with a named reason
instead of a value that would describe the replica. Schema findings are unaffected: a
schema is the same on every node. An instance whose role cannot be established is
treated exactly like a replica.

#### On a multi-tenant project, say which tenant

If the configuration looks multi-tenant — sibling connections under one naming scheme,
a tenant database prefix, or a known tenancy package — the run stops and asks. There is
no `--all-tenants`: an aggregate over tenant databases is a different claim from the
one this report makes.

```php
// config/sqlens.php
'audit' => [
    'tenancy' => [
        'mode' => 'explicit',      // 'none' on a single-database project
        'reference' => 'tenant_eu', // which tenant this report is about
    ],
],
```

The header then names that tenant and states that the findings describe it alone. If
the detection is wrong for your project, setting `mode` to `none` deliberately is a
valid answer — the check is a heuristic and says so.

#### Silence findings you have decided about

```php
'audit' => [
    'ignore' => [
        'rules' => ['PG.L5.FK_NO_INDEX'],          // everywhere
        'objects' => ['public.legacy_*'],          // these objects, every rule
        'pairs' => [                               // the precise form — prefer it
            ['rule' => 'PG.L5.NO_PRIMARY_KEY', 'objects' => ['public.events']],
        ],
    ],
],
```

Ignored findings are **suppressed, not filtered**: they stay counted, are listed under
what hid them, and the header says how many. An entry that matches nothing is reported
too, because an ignore list that has rotted looks exactly like one that is working. An
unknown rule id stops the run before it connects rather than silencing nothing.

### 6. Scan for security and privacy findings

`sqlens:security` examines the connection for security findings across every suite. It reads the
catalog; it never grants, revokes or repairs anything.

```bash
php artisan sqlens:security
```

The severity floor is its own gate, separate from the level. `--min-severity` sets it for one run,
and the environment profile presets it:

```bash
php artisan sqlens:security --min-severity=high
```

The privacy half is opt-in and heuristic: it reads column names, never values. Turn it on with
`sqlens.security.privacy.enabled`, and read
[the privacy pack page](https://docs.pushery.com/sqlens-for-laravel/security/privacy-pack/) first —
it says what the heuristic cannot do, and it is short.

Accepted values are `info`, `low`, `medium`, `high`, `critical`, and `none` to report everything
without letting any of it block.

SQLens can also call two outside tools — Squawk and the Postgres Language Server — and neither is
required: one that is not installed becomes an `undetermined` finding with a named reason rather than
silence. `plpgsql_check` is deliberately **not** among them, because it is a server extension that
would have to be installed on the database being audited. What covers that surface instead is on
[Optional analyzers](https://docs.pushery.com/sqlens-for-laravel/tools/optional-analyzers/).

#### Put the findings on the pull request, not in a log

`--format=sarif` writes the format GitHub code scanning ingests, and `--output` writes it to a file:

```bash
php artisan sqlens:security --format=sarif --output=sqlens.sarif
```

Upload that file with `github/codeql-action/upload-sarif` and each finding lands on the diff that
introduced it. `--format=github` writes workflow annotations instead, if you want them inline
without code scanning.

#### The privacy pack is opt-in

Personal-data findings depend on what a column MEANS, which is a judgment about your project rather
than about your database. So they are off until you say otherwise:

```php
// config/sqlens.php
'security' => [
    'privacy' => [
        'enabled' => true,
    ],
],
```

They then arrive as ordinary findings under the `privacy` category, subject to the same gate and the
same suppression rules as everything else.

#### Only one flag touches the network

```bash
php artisan sqlens:security --refresh-advisories
```

`--refresh-advisories` fetches the end-of-life data the version checks read. **It is the only thing
in this package that opens a network connection, and it is never a side effect of a check** — an
ordinary run works from what is already on disk and tells you when that data is old rather than
treating stale as current. Run it in a scheduled job, not in the job that gates your deploy.

### 7. Adopt on an existing project with a baseline

An established schema will report findings on the first run. Freeze them so the
linter reports only what is NEW from then on:

```bash
php artisan sqlens:baseline
```

- The baseline is written to `sqlens.baseline.path` — set it first (e.g.
  `.sqlens-baseline.json`, committed to the repo). It is a repo file, never a
  database write.
- Only failing findings are frozen; an undetermined is never baselined.
- `--dry-run` shows what would be written without touching the file; `--update`
  merges newly seen findings into an existing baseline additively; `--path`
  (repeatable) scopes which migrations to scan.
- The file is deterministic and merge-arm — one finding per line, no timestamp or
  absolute path — so two branches accepting different findings resolve line by
  line. Commit it, and fix or re-baseline as the schema evolves.

### 8. Accept a finding in the migration itself

When a finding is a deliberate, one-off choice, annotate the migration class
rather than baselining it. Both attributes take a mandatory `reason`, so the
acceptance is never silent:

```php
use Pushery\SQLens\Attributes\SqlensAllowDestructive;
use Pushery\SQLens\Attributes\SqlensIgnore;

// Accept a specific finding by rule id:
#[SqlensIgnore(rules: ['PG.L2.INDEX_NOT_CONCURRENT'], reason: 'one-row lookup table')]

// Accept the destructive family at once — DROP TABLE/COLUMN and TRUNCATE in up(), the
// deploy-window drop rule, and a WHERE-less mass UPDATE/DELETE — when the loss is
// intended. The finding is not hidden: it is reported as a named suppression with your
// reason. A project that is destructive by design can set `sqlens.allow_destructive`
// in config instead of annotating each migration.
#[SqlensAllowDestructive(reason: 'legacy table superseded and confirmed empty')]
class MyMigration extends Migration { /* … */ }
```

A third attribute answers the static-analysis rules instead of suppressing them, and it
takes two separate reasons because they are two separate questions:

```php
use Pushery\SQLens\Attributes\RawSql;

#[RawSql(
    // Why raw SQL rather than the query builder. Answers SEC.INJ.RAW_SQL_WITHOUT_REASON.
    reason: 'partitioned-table DDL; the query builder cannot express PARTITION OF',
    // Why a runtime value is in the statement's TEXT rather than in its parameters.
    // Answers SEC.INJ.RAW_INTERPOLATION, and only this argument does.
    interpolation: 'the suffix is a date this method formats — no engine binds an identifier',
)]
public function createPartition(string $suffix): void
{
    DB::statement("CREATE TABLE orders_{$suffix} PARTITION OF orders FOR VALUES …");
}
```

Write `interpolation:` only where a binding genuinely does not exist — an identifier, a
schema name, a DDL fragment. Where the value could be bound, bind it: `reason:` alone
leaves the interpolation finding standing, on purpose, so annotating for the policy rule
never switches the injection rule off with it.

It goes on a class, a method, a function, a closure or an arrow function, and covers
everything inside what it sits on. A class-level annotation is right for a class whose
whole job is DDL over computed names and too wide for one that has a single such method.

### 9. Reach the same engine from an agent, over MCP

This one step needs a package SQLens does not require:

```bash
composer require --dev laravel/mcp
php artisan sqlens:mcp
```

`laravel/mcp` is optional and deliberately not a dependency — it carries a server runtime that
every run without the MCP server never uses. Without it `sqlens:mcp` reports a named
`undetermined` and prints that install command rather than failing, so nothing else in this
skill is affected by skipping this step.

`sqlens:mcp` starts a Model Context Protocol server over stdio. Point an agent's MCP
configuration at that command and it can ask the same engine `sqlens:lint` runs — same
rules, same suppression, same three-valued answer. Nothing is duplicated for the agent:
the command and the server are two callers of one service, so a person and an agent can
never disagree about a migration neither of them changed.

Which tool answers which question:

- **`lint_pending`** — right after writing or editing a migration, before the commit.
  It lints what the project has not run yet and hands back structured findings, each
  carrying its `downtime_class`. Pass `file` to lint one named migration on the
  sub-second path an editor loop can afford; it opens no database connection at all.
  (The MCP tool takes one file; the `sqlens:lint` command takes as many as you name.)
- **`explain_rule`** — *before* trying to work around a finding. It returns the rule's
  own metadata: what it judges, why, its level and severity, and where the
  documentation is. Reading it is usually cheaper than the workaround.
- **`get_findings`** — to act on the run that already happened. It reads the report
  artifact a previous run wrote and never starts a new one, so asking "what did the last
  run find" cannot become a database run nobody asked for.
- **`get_debt_ledger`** — to see what the project has knowingly deferred, and how long
  it has been deferred for.

Every answer is three-valued. A run that could not happen comes back `undetermined` with
a named reason and never as an empty finding list — "found nothing" and "could not look"
are different answers, and only one of them is safe to act on.

Configure the surface under `agent.mcp` in `config/sqlens.php`: which tools the server
exposes, which connection it answers about, where `get_findings` reads its report, and
the ceiling on how many findings one answer may carry (crossing it is reported as
crossing it, never a quiet truncation).

**Tools that touch a database are absent unless a person switched them on, by name.** A
server that could run migrations for real, or check a production instance, is a decision
about a project's databases — not one an agent makes for it, and not one this skill asks
for. There is no switch that enables them all at once, deliberately: enabling one
dangerous capability must not be a decision about every dangerous capability the package
will ever have. If you find a tool missing, say so and let the person decide; do not
edit the configuration to add it.

### 10. Keep the SQL in your repository to one style

`sqlens:format` rewrites `.sql` files to a house style; `--check` answers whether it *would* and
exits non-zero if so, which is the form a CI step uses. `--diff` shows the change without making it.

```bash
php artisan sqlens:format          # rewrite
php artisan sqlens:format --check  # a verdict a pipeline can act on
php artisan sqlens:format --diff   # a unified diff, written nowhere
php artisan sqlens:format database/sql/report.sql   # one file, as an argument or --path=
```

`--format=console|json|github` picks the report, the same spelling as every other command — yes,
`--format` on `sqlens:format`, and the collision is deliberate rather than an oversight. `console`
is the default and goes to STDERR; `json` and `github` go to STDOUT, so `--format=json > report.json`
yields a file holding nothing but the document. An unknown value is a misconfiguration, refused
before anything is written, never a quiet fall back to `console`.

In `auto` the run names any backend it could not use (`TOOL.PGFORMATTER.MISSING`) and what
installing it would add — the fallback to the built-in core is right, but a silent one leaves two
machines formatting differently with nothing saying so. `--strict-tools` makes that a failure.

Which files a run finds comes from `sqlens.format.paths` (empty: the app's migration paths),
`exclude` (default `['database/schema/*']`, because `schema:dump` rewrites those anyway) and
`extensions` (default `['sql']`). ⚠️ `php` is **reserved** and cannot be added — a migration is a PHP
file, and reading one as SQL rewrites the whole file as a single statement. `vendor/`,
`node_modules/` and `storage/` are never walked into, and symlinks are not followed.

`--diff` and `--check` are not the same question. `--diff` shows the work and leaves the exit code
alone; `--check` returns the verdict. Run `--diff` to decide whether to run the write, `--check` in
the pipeline, and `--check --diff` when you want both.

⚠️ **`.sql` files only.** A Laravel migration is a PHP file, and running a SQL formatter over one
does not format the SQL inside its heredoc — it reads PHP as SQL and rewrites the whole file. The
scanner refuses a `.php` path even when you name it explicitly, and generated `database/schema/*.sql`
dumps are left alone.

It runs with **no database**: where the dialect cannot be resolved from your connection, the run
says so and formats with the dialect-neutral built-in backend. Nothing to install.

Three backends sit behind one seam — `pgformatter`, `sqlfluff`, and the built-in `php` core. `auto`
picks the best **installed** one. Naming one is a promise that it is installed: a named backend that
cannot run is refused rather than quietly replaced, because a replacement would give you output you
did not ask for and the machine that *does* have the binary would rewrite every file.

### 11. Turn on runtime guardrails with one config key

`sqlens.guard.profile` names a profile and that is the whole setup — no command, no route, no
middleware, no line in `AppServiceProvider`. Three examples ship: `local`, `ci`, `production`.

```php
// config/sqlens.php
'guard' => ['profile' => env('SQLENS_GUARD')],
```

It sets Eloquent's strictness switches, reports a query past a threshold, reports a *request* past a
cumulative one, and names DDL a request issued outside a migration.

- **Off means absent, not cheap.** With no profile, nothing is bound and no query listener is
  registered.
- **A profile name nothing defines is an error at boot**, never "off" — a typo would otherwise
  disable every guardrail while the config still reads as though they are on.
- **`throw` is false outside `local`.** The switch stays on and the *handler* reports, so a lazy load
  in production is logged rather than turned into a broken page.
- **Bindings never reach the log as values.** With `include_bindings` on you get `string(18)`, not
  the address that was bound.

## Examples

Lint the pending migrations of the default connection:

```bash
php artisan sqlens:lint
```

Confirm the environment and that SQLens resolves the connection you intend to lint:

```bash
php artisan sqlens:doctor
```

Check that the repository's SQL is formatted, without changing anything:

```bash
php artisan sqlens:format --check
```

## Anti-Patterns

- Do not document package internals here; keep the skill focused on adoption
  in Laravel applications.
- Do not duplicate the full README; link the deeper reference material instead
  and keep this skill small enough to load and apply quickly.

## Levels and security severity are two dials, not one

Answer this before touching the configuration, because it is the single most common
misreading of a SQLens report:

- **Level** models how *pedantic* a project wants to be. It is an appetite, turned up
  over time like a Larastan level: level `n` runs every rule at level `<= n`.
- **Severity** models *risk*, and risk is not a matter of appetite. A password literal
  in a migration is critical whether or not the project has got round to level 5.

So security and privacy findings are **not measured against the level at all**. They
answer to `security.min_severity`, which means a critical security finding stops a
build in a level-0 run — which is exactly where it matters, because a project early in
its adoption runs a low level. Measured against the level, such a finding would be
invisible in the projects most likely to have it.

Reading a report with that in mind:

- Findings come in two sections, "Level findings" and "Security findings"; a finding
  appears in exactly one of them.
- The JSON says which gate stopped a finding in `blocked_by` (`level`, `severity`, or
  absent), and each finding carries only the dial that applies to it — a security
  finding has a `severity` and **no** `level`.
- The summary keeps `level_gate` and `severity_gate` apart, each with its own
  threshold and its own breach count. They are never merged into one number.
- The risk gate also reports what it could not look at: security checks that came back
  `undetermined` are counted beside the breaches, never folded into them. On a managed
  database that second number is often the larger one, and "0 breaching" over a run
  that answered almost nothing would be a green nobody earned.

Two things that follow, and that people get wrong in opposite directions:

- **`--category` is a scope, not an off switch.** It runs *before* the gates, so
  leaving `security` out does not pass the security gate — it means no security rule
  ran and the report says nothing about security. The active filters are named in the
  run header for exactly that reason.
- **Changing one dial never moves the other.** A profile that raises the level leaves
  the floor where it was, and `--min-severity` does not touch the level.


## What a `composer update` may change

A minor release of SQLens may make your build fail where it passed yesterday, and there is exactly
one way that happens on purpose. Knowing which one saves you from pinning the version — which is the
outcome nobody wants, because a pinned project stops getting the fixes too.

- **A new rule arrives as `preview` and is opt-in.** It does not join the level defaults until a
  major, so a minor never turns on a rule you did not ask for.
- **The one exception: a security severity may be RAISED in a minor**, and the changelog says so in
  a callout. A finding that turns out to be worse than first judged should not wait for a major —
  waiting would protect the release schedule at your expense. This is the case that can newly stop
  a build, and it is deliberate.
- **Lowering a severity, renaming a rule id, or removing one is breaking** and waits for a major.
  Your baseline file and your `ignore` lists key on rule ids, so those ids are a contract.

### The tier is in the output, not only here

Every rule carries one of three tiers, and you can see it where you read the finding rather than
having to look it up:

| Tier | What it promises |
| --- | --- |
| `stable` | The id, message prefix and meaning follow the policy above. |
| `preview` | It works and is opt-in. The id and message may still change in a minor. |
| `experimental` | Available to try. It may change or disappear in any release. |

In the console a non-stable finding is marked after its rule id — `PG.L2.INDEX_NOT_CONCURRENT
[preview]`. In `--format=json` and in SARIF the same answer is the `stability` field. So a run that
newly fails can be read without leaving the terminal: if the rule that stopped you is marked
`preview`, you opted into it.

### What this means for a CI upgrade

Read the changelog callouts before a minor bump, and keep the security floor explicit in your
configuration rather than relying on a default. `security.min_severity` is the dial that decides
whether a raised severity reaches your build at all.

### 12. Give your coding agents the rules before they write the migration

SQLens contains no model. It writes text for whatever agent you use and verifies, deterministically,
what that agent hands back — the half an agent cannot do for itself.

Write the rule set your project actually enforces into the context files your agents already read:

```bash
php artisan sqlens:agent-rules
```

That produces three files, one per target, and touches nothing else:

| `--target` | File it writes |
|---|---|
| `claude` | a marked section inside `CLAUDE.md` |
| `cursor` | `.cursor/rules/sqlens-migrations.mdc` |
| `copilot` | `.github/instructions/sqlens-migrations.instructions.md` |

Every target at once by default, or one at a time with `--target=`. A single target can be sent
somewhere else with `--output=<path>`. No database is opened, so this works in a fresh clone and offline.

If the project's default connection is SQLite, name the one you deploy against with
`--connection=pgsql`. SQLens ships no rules for SQLite, so the command refuses with that reason
instead of writing an empty catalog.

**It writes what YOUR project enforces, not the whole catalog.** Raise the level, add an ignore
entry or pin `assume_server_version`, and the files change with it. Guidance that named checks your
pipeline does not run would be wrong in the direction nobody notices — an agent would follow a rule
that never fires and skip one that does.

**The `CLAUDE.md` section is replaced, never duplicated.** Everything you wrote around it comes back
byte for byte, so the second run is safe and so is the twentieth.

Commit all three files, then keep them honest in your own CI:

```yaml
- run: php artisan sqlens:agent-rules --check
```

`--check` writes nothing at all — including when a target file is missing, which is what a fresh
clone looks like and exactly where a write path would silently paper over the gap. It exits `0` when
every file is current, `1` on a deviation, and `2` when the invocation itself was wrong; a job can
branch on the number before reading the message.

### 13. Close the loop with a report the agent can act on

```bash
php artisan sqlens:lint --format=agent
```

One markdown document per run, in the order worth acting on: what the run was, what it found, what
to fix first, what it could NOT answer, and what not to do about any of it. Paste it to your agent
as it is.

Two properties make it usable rather than merely readable:

- **The format never changes the verdict.** `--format=agent` and `--format=json` over the same state
  end in the same exit code, because both read the same gate decision. So "the agent says it is
  fixed" is settled by running the command again, not by the claim.
- **A run that could not answer is never rendered as clean.** The undetermined section is always
  present — it says `0 undetermined` out loud when it is empty — and every entry carries its named
  reason and the next thing to do about it. An agent that reads a report with no failure list
  concludes the run was clean and says so; that is the mistake this section exists to prevent.

Write it to a file with `--output=<path>` when you want to attach it to a pull request.
