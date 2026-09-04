# Changelog

All notable changes to `pushery/sqlens-for-laravel` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-05

### Added

- `#[NoSqlOnDriver]` says where a migration's emptiness is deliberate, so `CAP.L0.NOT_CAPTURABLE` stops reporting a decision you already made. A migration that emits nothing on one driver — a partial index is a PostgreSQL feature, a storage-engine change means nothing outside MySQL — annotates the method or the class with the driver and a reason, and the rule stays quiet on exactly that driver. It still reports on a driver you did not name, so the attribute cannot become a blanket switch that merely sits closer to the code, and a misspelled driver name excuses nothing anywhere, which is how the typo shows up instead of quietly disabling the check. Unlike a baseline entry, it moves with the file when you rename it, it sits where the decision was made rather than in another document, and it stops applying the moment the migration becomes empty for some other reason. The reason is required; an empty one is treated as though the attribute were absent.

- A formatter backend can now be asked which version of itself is installed, without formatting a file first. `SqlFormatter::version()` returns the installed version, or `null` when the question cannot be answered — the binary is absent, or it did not respond to the probe. It never throws: a backend is something that improves the output, never something a run requires, so asking about a missing one must not be what fails. The built-in PHP core answers with the package's own version rather than `null`, because it ships inside the package and cannot be missing, and `null` would put the one backend that always works in the same column as the ones that are not installed. Asking repeatedly costs one probe: the answer is a fact about the machine, identical for the first file and the two-hundredth.

### Changed

- **If you implement `CaptureRule` yourself, `appliesTo()` now receives the run's `SubjectContext` as a second argument.** Some capture questions depend on which driver the run is on, and the answer has to exist before a finding does — `evaluate()` must return one, so a rule that decides in there that it should stay quiet has no way to say so.

- **If you implement `SqlFormatter` yourself, you now need a `version()` method.** The interface is the seam behind which a custom backend plugs in, so adding a method to it is a change your implementation has to follow. Returning `null` is a valid answer and the right one when you cannot determine a version.

## [0.2.0] - 2026-09-04

### Added

- `format.binaries.<backend>` takes a third answer: `false` says this project does without that backend. It is a decision rather than a gap, and the run treats it as one — the backend is not named as something that would have been added, and `--strict-tools` has nothing to fail over. A backend that is merely absent is still a loss and still fails a strict run, because the machine that has it formats differently and the output is committed. Naming a switched-off backend is refused rather than substituted, with a message pointing at the key. The built-in core cannot be switched off: it is what makes the suite work with no binaries at all.
- The interpolation rule now reads what the engine's own escaping did to a value, and treats the two forms differently because they are not equally strong. `$connection->escape($value)` is `PDO::quote()` — the result is a value literal that cannot change the statement's grammar or select a different object, which is what a binding gives you at a position that accepts no binding, so the finding goes. `$connection->getQueryGrammar()->wrap($name)` is **not** the same guarantee: measured against both shipped grammars, it stops the breakout (`x"; DROP…` comes back quoted and doubled) and not the object choice (`other_schema.secrets` comes back as two quoted segments). So that finding stays, and only the advice changes — from "pass it as a binding", which no engine accepts for an identifier, to constraining the value to a set you wrote. `wrap()` around a `DB::raw()` is refused outright: an `Expression` is handed back verbatim, so the argument must be provably a string.

- The console summary now names the denominator behind its counts: `summary: 0 fail, 4 undetermined, 0 suppressed — over 32 migrations`. Every number on that line was a numerator, and a numerator alone cannot separate "nothing was wrong" from "almost nothing was read". A consuming project met exactly that: `--path=database/migrations` lints one directory level — because that is what Laravel's own `getMigrationFiles()` globs, so `migrate --path=` does not run the nested migrations either — and a tree of 32 central and 298 tenant migrations reported a clean run and exit 0 over 32 files. The behavior is Laravel's and stays; what was missing was any way to see it. A run whose producer has no file list to count, such as `sqlens:audit`, states no number rather than a misleading zero.

### Changed

- `security.include_vendor_migrations` now decides whether a run READS a package's migrations, not only how it classifies them once it has. Off — the default — a `sqlens:lint` run no longer loads or pretend-executes a migration that ships inside `vendor/`, so a first run after `composer require` can no longer fail on findings inside another package's migrations while reporting nothing about the project's own. The switch keeps its old meaning as well; the setting is one question asked one step earlier. Two runs are deliberately not filtered: one whose paths you named (`--path`, `migration_paths`, `--file`), and `sqlens:predeploy`, because a package's migration really does run during a deploy and can take a lock like any other. If every pending migration turns out to be a package's, the run reports `LINT.SKIPPED.ONLY_VENDOR_MIGRATIONS` rather than an empty result that would read as clean.
- The interpolation finding now names what to do when no binding form exists. An identifier, a schema name, or DDL assembled from an enum takes no placeholder in any engine, so `statement('… = ?', [$value])` was advice that could not be followed there — and with `analyse.exclude_paths` deliberately not reaching the injection rules, a project that could not find the alternative was left with turning the rule off or turning the analyzer off. The alternative existed all along in PHPStan's own `ignoreErrors`, keyed on the rule's identifier and scoped to a path; it is now named in the finding itself, in `extension.neon`, and on both documentation pages. The identifier is derived from the rule rather than written by hand, and a test drives the real analyzer to prove the block removes exactly those findings and leaves every other rule reporting.
- The rule page and the bundled example register both claimed every method the rule looks at takes a bindings array. `DB::raw()` and `DB::unprepared()` do not, and the page's list of fragment methods was also missing `raw`. Both now say what the sink register says.

### Fixed

- A `#[RawSql(reason: …)]` whose reason was wrapped across lines silently answered nothing. Only a bare string literal was read, so `'a ' . 'b'` — the way PHP wraps a sentence, and the way a reason worth writing usually has to be written — left the finding standing while looking exactly like enforcement. Literals joined with `.` are now read as one reason. A constant or a variable anywhere in the expression still refuses the whole of it: reading one would mean evaluating project code during analysis, and that decision is unchanged.
- A derived run context silently lost its `guard_profile`. `RunContext::copyWith()` took the value as a parameter and never passed it on, so every context derived through `withDriftMode()` and its siblings reported a run with no guard profile — a legal state, and therefore invisible from the outside. Found while adding a field beside it, in the one field no test compared.

- `#[RawSql(reason: '…')]` did nothing on an anonymous class, so it did nothing in a Laravel migration — the form every migration has taken since Laravel 9, and where raw DDL usually lives. The rule's own message recommends the attribute, and the only remaining answers were to turn the rule off or to exclude the migrations directory, both of which silence more than the finding. The collector was skipping any class without a namespaced name, which an anonymous class never has; it now joins on the name PHPStan gives it, which is the same name the call site reports. Both placements work: on the class and on the method.

- A database whose name contains `livewire` was read as a production connection, so every database-creating mode refused to run against it — in `local`, and with `--force`, because the production check sits above both. The marker `live` matched it as a segment prefix, and naming the database after the application is what Herd, Valet and `laravel new` all produce. `livewire` is now recognized as a coincidence rather than a marker. The exemption is for that segment alone: `livewire_production` is still production, and every name the obvious alternative cure would have dropped with it — `livedb`, `proddb`, `liveserver` — is still caught. The detector can also name the segment and marker behind a verdict now, so the reason no longer has to be found by removing one segment at a time.

- The shipped config comment for `connection` said `null` means the framework's default connection, full stop. True for capture and lint, and false for `sqlens:audit`, which deliberately does not consult `database.default`: with more than one supported connection it refuses and lists the candidates, because which instance was read is part of what the report asserts and a primary and its replica disagree about settings, about lag, sometimes about schema. A project meeting that refusal had no way to anticipate it from the file it had just configured. The comment now states both halves, and one test reads the block out of the shipped file while driving the resolver, so the prose and the behavior cannot drift apart again.

## [0.1.2] - 2026-09-04

### Fixed

- The package can be installed again on Symfony 8.0 and on Composer 2.1. `symfony/console`, `symfony/process` and `composer-runtime-api` each asked for a version higher than anything the code actually uses — the numbers were whichever ones happened to be installed the day they were first written down, not a requirement. Measured against the Symfony 8.0.0 tag before lowering them: every method, constructor and type this package touches is present there and unchanged. Laravel itself was never affected — `illuminate/*` has asked for `^13.0` since the first release and still does. A test now states every one of these floors outright, so a future one cannot tighten without somebody deciding to.

## [0.1.1] - 2026-09-03

### Fixed

- The shadow orphan sweep reported the databases it dropped in whatever order the catalog happened to return them, so the same state could produce two different reports. `pg_database` and `information_schema.schemata` promise no order; the listing now has one, and it is part of the catalog contract.
- The README's Laravel badge rendered an empty field. It read from a service that derives its answer from `laravel/framework`, which this package deliberately does not declare — it requires the `illuminate/*` components it actually uses. The badge now reads the constraint from Packagist and shows the Laravel major the package supports.

## [0.1.0] - 2026-09-03

The first public release. Nothing before it ever shipped, so there is no earlier version for any of this to be a change *from* — read the sections below as a description of what the package **is**, not as a diff.

### The shape of it

SQLens is a database safety toolkit for Laravel applications on PostgreSQL 18+ and MySQL 8.4+. It reads the migrations you are about to run and the schema you already have, and it says what they will cost.

Three principles govern every part of it, and they are worth stating first because they explain most of the design decisions further down.

**No silent green.** Every result is one of three values — `pass`, `fail`, `undetermined` — never two. A check that cannot run is reported as `undetermined` with a named reason, never folded into the passing set. On a managed database, where a great deal of the catalog is simply not exposed to any role you can hold, that third value is the normal answer rather than an edge case, and a tool that hid it would be reporting a clean bill of health for questions it never asked.

**Primum non nocere.** The tool must not harm the database it is pointed at. It takes no lock of its own, issues no write, and reads catalog and state views only. It sets its own session timeouts so it cannot become the thing that hangs. It keeps no state in your database at all — the migration debt account is a file in your repository, not a table. The two modes that do create a database create a throwaway one, and both sit behind a production guard that refuses by default.

**Determinism.** The same state produces the same result on a developer's machine and in CI. That is held by the `assume_server_version` pin, strict tool mode, and a canonicalization layer every rule works on rather than raw SQL. There is deliberately no "fast" path that disagrees with a "correct" one.

### Added

**Eleven commands.**

- **`sqlens:lint`** — reads the migrations that have not run yet and reports what they will do to a live database. It obtains their SQL through Laravel's own grammar rather than by parsing your migration source, so the advice is about the statement your app will really send: by default without executing it (`--pretend`), or by running it against a throwaway shadow database it creates and drops itself (`--shadow`). `--roundtrip` replays up, down and up again in that shadow database to test whether `down()` is a real inverse. A single-file fast path (`--file`) needs no database at all and is built for a pre-commit hook.
- **`sqlens:audit`** — reads the catalog of a database that already exists and judges the schema as it stands. It will not guess which connection, which read host, or which tenant the report is about: where the configuration leaves a choice, the run stops and says so rather than describing one server under another one's name.
- **`sqlens:security`** — roles, grants, transport, server configuration, row-level security, injection and unencrypted columns, across every suite. Gated by a severity axis of its own rather than by the strictness level, so lowering the level band cannot silence it.
- **`sqlens:predeploy`** — reads the target database immediately before a deploy: read-only, fail-closed, and bounded by a time budget so it can never be the thing that hangs a release. It checks what the migration is about to walk into — a lock blocker, replication lag, disk headroom, a missing privilege, a read-only target, a version skew.
- **`sqlens:postdeploy`** — reads what the deploy left behind: an index that ended up invalid, a constraint that was never validated, an orphaned transition object. Read-only, catalog-only, once.
- **`sqlens:drift`** — compares what the database holds against what the migrations describe, with an exclude file for the differences a project has accepted, each needing a reason.
- **`sqlens:baseline`** — writes the findings of today into a file you commit, so a project can adopt the tool on a schema it inherited without a red build on day one.
- **`sqlens:format`** — one house style for the SQL in your migrations, with a `--check` mode a CI step can act on and a `--diff` mode that shows what a write would do without doing it. Three backends behind one seam; the built-in one needs nothing installed.
- **`sqlens:doctor`** — what SQLens can actually see from here: each connection's real server version, and each optional tool's version or its absence. An absent tool's line names what you lose by not having it rather than merely reporting it missing.
- **`sqlens:mcp`** — serves the same engine the commands use to an AI agent over stdio. Every tool is read-only unless named individually with `--enable-tool`; there is deliberately no option that enables them all.
- **`sqlens:agent-rules`** — writes the project's active rule set into its coding agents' context files, so an agent knows a rule before it writes the migration rather than after the linter rejects it. Opens no database, and its `--check` mode treats a missing artifact as a deviation rather than creating it.

**225 rules, every one of them documented.** The catalog ships as a data artifact with a published page per rule id, and the count is held rather than claimed: 225 entries, 225 pages, zero pending. Every finding carries the URL of its own page, derived from the rule id rather than written by hand, so a link a shipped finding already carries cannot drift.

By category: 135 safety, 57 security, 17 idiom, 7 performance, 6 convention, 3 privacy. By maturity: 220 stable, 3 preview, 2 experimental.

**Ten cumulative strictness levels, and the level is an appetite rather than a severity.** Level 4 runs everything up to 4. The distribution is deliberately front-loaded — 136 rules sit at level 0, and the bands above it add taste rather than danger. Level 6 tells you about choices a reasonable engineer might have made on purpose, and reading that band as a defect list is the commonest way to misread it.

**A maturity axis that keeps a minor release from breaking your pipeline.** A new rule lands as `preview` and runs only on request. An unconfigured project gets stable rules only — the opposite default to categories, where unconfigured means all, and the difference is the point: an unset category axis means nobody expressed a preference, an unset maturity axis is the versioning promise doing its job.

**A `downtime_class` on every finding that can change a statement's locking behavior** — `online`, `blocking` or `rewrite` — so a deploy script can ask whether this release needs a maintenance window without knowing which rules carry the answer. 58 entries carry one: 38 rules and 20 deploy checks, distributed 38 online, 18 blocking, 2 rewrite. The rest carry none because the question does not apply to them — a run notice describes the run, and a rule that only reads the catalog is not about a statement that takes a lock. The JSON envelope exposes the worst one in the run directly rather than making a consumer re-derive an ordering that is this package's judgment and is not alphabetical.

**A severity axis of its own.** 78 of the 225 entries carry a severity: the 58 security and privacy rules, which answer to it instead of the level gate, plus 19 deploy checks and one debt notice, where a severity orders several failures rather than gating any of them. Across all of them: 7 critical, 32 high, 28 medium, 8 low, 3 info. The other 147 entries answer to the level gate. The two gates are never merged — a strictness choice and a security risk are different facts, and one number cannot carry both.

**Five reporters over one result** — console, JSON, GitHub annotations, SARIF, and an agent format — plus registration for a custom one. The SARIF output is validated against the real schema rather than eyeballed, over a populated run, an empty one and a catalog-only one.

**A four-value exit-code contract** a pipeline branches on: clean, findings above the gate, misconfiguration, and undetermined under strict mode. Misconfiguration beats everything, including a run with no findings at all, because a tool that cannot trust its own setup must never report green.

**A pre-scan that refuses to execute a migration it cannot execute safely.** A migration that sends mail, calls an HTTP endpoint, guards on introspection, or reaches its effect through your own code is reported and never pretend-executed. Recognizing a side effect is not the same as preventing one, and the honest move is to decline rather than to run it and hope.

**A migration debt account.** The two-step patterns this tool recommends — expand then contract, add then validate — leave a second step somebody has to actually take. The ledger is a file in your repository that records which ones are outstanding, how long they have been, and which have since been resolved. It is a repository file rather than a table on purpose: a safety tool that writes to the database it is auditing has given up the property that makes it safe.

**A supported-version floor that qualifies the report instead of withholding it.** Below the floor the run still produces its findings and says unmistakably what they are worth — a named `undetermined`, a marker in the run header, and a failing exit under strict mode. The message states that findings may be wrong in both directions, because the one-sided reading misses the dangerous half: below the floor no rule was ever written for the hazards that only exist there, so a clean report is the least informative result the tool can produce rather than the best one.

**A bundled Laravel Boost skill**, so an assistant working inside a consuming application has the adoption guidance without being told where to look.

### Security

The package connects to production databases and shells out to external binaries, so its own posture is part of what it ships rather than an implementation detail.

- **It takes no lock of its own, and writes nothing to the database it is pointed at.** Every read goes to a catalog or state view. The two modes that need to execute a migration — `--shadow` and `--roundtrip` — do it in a throwaway database they create and drop themselves, never in yours, and both refuse to run against a production connection unless the guard is explicitly lifted. The one network call in the package is `sqlens:security --refresh-advisories`, which is never a side effect of a check and runs before anything connects.
- **Credentials are redacted from every output** — reports, the JSON envelope, the agent artifacts and the debt ledger.
- **The MCP server is read-only by default.** A mutating tool is exposed only by being named, one at a time.
- **Database-creating modes sit behind a production guard** that refuses by default and reports which of its three checks held a blocked run, because the three need different fixes.
- **A dedicated read-only audit connection is supported**, so the role that reads your catalog need not be the role your application runs as.

### What 0.1.0 does not do

- **The public API is not frozen.** It is documented, and it is what a 1.0 will commit to, but a field or a flag may still change in a minor release before then.
- **PostgreSQL and MySQL only.** MariaDB is refused by name rather than half-supported: it answers Laravel's `mysql` driver and does not share its semantics, and the divergences are exactly what this tool reasons about — so advice about it would be confident, specific, and about another product. SQLite and SQL Server are declared non-goals for the same reason.
- **One shipped locale.** Everything this package emits goes to a terminal, a CI annotation, a SARIF file or an agent artifact, and a translated `ALTER TABLE` warning still contains `ALTER TABLE`.
- **Statistics-dependent rules are opt-in and honest about it.** The index-usage rules answer from counters that can be reset, so they ship `experimental` and report nothing until you ask for them. The source-reading pre-scan detectors ship `preview` for the same reason.
- **Levels 8 and 9 are thin** — 4 and 6 rules. The convention band is defined and only lightly populated.
- **The MCP server cannot shield standard output from what precedes it.** It takes the channel as early as a service provider can, diverts stray writes to the diagnostic stream and keeps `stdout` for protocol frames — but a message PHP emits while loading a file happens in the autoloader, before any provider boots. A host application whose dependencies emit a compile-time deprecation can therefore corrupt the frame stream, and no code inside the server can intercept it. The client reports a protocol error; the cause is on the other side of the boundary.

### A note on this file

Everything above is the first release, so there is nothing for it to be a change *from*. The development history that produced it — several hundred entries, each arguing a decision through — lives in the git log, where it belongs. From 0.2.0 on, this file records changes.
