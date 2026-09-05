<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | SQLens for Laravel
    |--------------------------------------------------------------------------
    |
    | Publish this file with:
    |
    |     php artisan vendor:publish --tag=sqlens-config
    |
    | Drift trap — read before editing a published copy: Laravel merges a
    | package config with mergeConfigFrom(), which is a SHALLOW array_merge, NOT
    | a recursive merge. A nested section you do not repeat in your published
    | copy is REPLACED wholesale by your copy, not merged with the package
    | default — so a key added to the package in a later release silently never
    | reaches an app that published an older copy. Keep a published config
    | minimal (only the keys you actually override) so new package keys keep
    | flowing through, and re-diff it against this file after every upgrade.
    |
    | Every key in this file is validated against a strict schema before any
    | suite runs: an unknown key, a wrong type, or an out-of-range value fails
    | the run with the misconfiguration exit code and a message naming the key —
    | never a silent no-op. That includes any not-yet-active placeholder you
    | uncomment early: it fails loudly until its suite ships.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Connection
    |--------------------------------------------------------------------------
    |
    | The database connection SQLens resolves, canonicalizes, and audits against.
    | Set it to a named connection to target a specific one — deliberately NOT a
    | hard-coded 'pgsql', because guessing a connection is exactly the resolution
    | heuristic this package refuses.
    |
    | `null` does NOT mean the same thing in every suite, and the difference is
    | worth reading once:
    |
    |   capture, lint   the host application's default connection,
    |                   config('database.default').
    |
    |   sqlens:audit    that default is NOT consulted. With exactly one supported
    |                   connection the audit takes it and names it in the report.
    |                   With more than one it REFUSES and lists the candidates,
    |                   exiting 2. Pass --connection for a one-off, or name one
    |                   here for good.
    |
    | The audit is stricter on purpose: which instance was read is part of what
    | the report asserts, and a primary and its replica disagree about settings,
    | about lag, sometimes about schema. Silently taking one would put a claim in
    | the report that nobody made, and its reader would have no way to notice.
    |
    */

    'connection' => null,

    /*
    |--------------------------------------------------------------------------
    | Host
    |--------------------------------------------------------------------------
    |
    | The ONE host to address when the connection configures a read/write split.
    | Laravel picks a read host at RANDOM from `read.host`, so on a split
    | connection two runs against the same cluster can read two different servers
    | — and a report that does not know which server it read is not a report.
    | SQLens therefore refuses to guess: a connection offering several read hosts
    | and no pin aborts as a misconfiguration, naming every host and this key.
    |
    | `null` means "decide per run" (`--host=`), which is right for a project whose
    | topology is unambiguous or which pins from CI. A host that the connection
    | does not offer is refused rather than dialed — pinning a server outside the
    | configured topology is a typo far more often than it is an intention.
    |
    | Docs: https://docs.pushery.com/sqlens-for-laravel/read-write-split/
    |
    */

    'host' => null,

    /*
    |--------------------------------------------------------------------------
    | Migration paths
    |--------------------------------------------------------------------------
    |
    | The migration paths the lint suite scans, as repo-relative paths. Empty
    | means the application's registered migration paths (database/migrations plus
    | any a package registered) — the same default a run with no --path uses. The
    | resolution order is --path (per run) over this list over the application's
    | registered paths, so this is a convenience default for a project that always
    | lints the same non-default paths, never a second source the flag has to fight.
    |
    */

    'migration_paths' => [],

    /*
    |--------------------------------------------------------------------------
    | Level
    |--------------------------------------------------------------------------
    |
    | The cumulative strictness level 0–9. A higher level is a superset of every
    | level below it: level 4 runs everything up to 4. Security and privacy
    | rules ignore this gate — they are gated by the severity axis below.
    |
    */

    'level' => 0,

    /*
    |--------------------------------------------------------------------------
    | Categories
    |--------------------------------------------------------------------------
    |
    | The categories a run is scoped to — the second filter axis, orthogonal to
    | the level. Any of: safety, performance, idiom, convention, security,
    | privacy. An empty list means every category (no filter); the --category
    | option overrides this per run. A category that filters away every rule is
    | reported as undetermined, never as a silent pass.
    |
    */

    'categories' => [],

    /*
    |--------------------------------------------------------------------------
    | Stability
    |--------------------------------------------------------------------------
    |
    | Which maturity tiers a run admits, beyond the stable ones that always run.
    | Empty means STABLE ONLY — and that default is the whole versioning promise:
    | a new rule lands as `preview` and runs only on request, so a minor release
    | cannot start failing a pipeline over code nobody touched.
    |
    | Note this is the opposite default to `categories`, where empty means all.
    | An unconfigured category axis means the operator expressed no preference; an
    | unconfigured stability axis is the contract doing its job.
    |
    | Opt in with ['preview'] to see rules that are complete but still settling,
    | or ['preview', 'experimental'] to include the ones that may still be wrong.
    |
    */

    'stability' => [],

    /*
    |--------------------------------------------------------------------------
    | Mode
    |--------------------------------------------------------------------------
    |
    | How SQLens obtains the SQL it reasons about: 'pretend' collects it via
    | Laravel's --pretend without executing, 'shadow' runs it against a
    | throwaway shadow database and reads the catalog back, 'static' reads the
    | migration source without a database. The mode appears in every run header
    | because the same migration can yield different findings per mode.
    |
    */

    'mode' => 'static',

    /*
    |--------------------------------------------------------------------------
    | Profile
    |--------------------------------------------------------------------------
    |
    | The environment profile a run executes under: 'local', 'ci', or
    | 'predeploy'. It appears in the run header so a reader knows whether a
    | result came from a lenient local run or a strict pre-deploy gate.
    |
    */

    'profile' => 'local',

    /*
    |--------------------------------------------------------------------------
    | Strict flags
    |--------------------------------------------------------------------------
    |
    | strict_tools: a missing or version-drifted external tool is a failure,
    | not a skipped check. strict_undetermined: a check that could not run
    | (reported as undetermined, never as a pass) escalates to a failing exit
    | code. Both belong on in CI and pre-deploy gates — an undetermined the
    | pipeline tolerates silently is a green that proves nothing.
    |
    */

    'strict_tools' => false,

    'strict_undetermined' => false,

    /*
    |--------------------------------------------------------------------------
    | Allow destructive operations
    |--------------------------------------------------------------------------
    |
    | The project-wide opt-in for the destructive rules — the level-1 family (DROP
    | TABLE, DROP COLUMN, TRUNCATE, and a mass UPDATE/DELETE with no WHERE) and the
    | level-4 deploy-window rule. It NEVER hides a destructive operation: when it is
    | on, the finding still appears in the run, moved to the suppressed list with a
    | named reason ("allowed project-wide by sqlens.allow_destructive"), so the
    | report keeps showing that the migration destroys data — the opt-in changes the
    | presentation, not the fact. Off is the strict, safe default; a single migration
    | can opt in on its own instead, in code and with its own reason, via
    | #[SqlensAllowDestructive].
    |
    */

    'allow_destructive' => false,

    /*
    |--------------------------------------------------------------------------
    | Use statistics
    |--------------------------------------------------------------------------
    |
    | Whether checks may reason about the server's table statistics — row counts,
    | index selectivity, bloat. They make a finding sharper ("this rewrites 40M
    | rows"), but they are a property of the instance that answered, not of the
    | migration, so they are off where reproducibility matters more than depth.
    |
    | The statistics reader itself arrives with the audit suite. Until it does,
    | turning this ON does not fabricate an answer: a statistics-dependent check
    | reports `undetermined` with a named reason, because "we could not read the
    | statistics" and "the statistics say you are fine" are not the same result.
    | With it OFF such a check does not run at all. Neither is ever a silent pass.
    |
    */

    'use_statistics' => false,

    /*
    |--------------------------------------------------------------------------
    | Assume server version
    |--------------------------------------------------------------------------
    |
    | Pins the server version SQLens reasons about (e.g. '18.0' or '8.4.3'), so
    | the same input yields the same result on a dev Mac and in CI regardless of
    | the server that happens to answer (determinism). `null` means the detected
    | version of the live server is used — and shown as detected, never as
    | pinned, in the run header.
    |
    | The format is strict: `18`, `18.2` or `18.2.1`, and nothing else. A pin is
    | read exactly or refused with a named reason — never approximated. `18.x`
    | would otherwise be read as exactly 18.0, quietly narrower than the "any 18"
    | it means, and a rule written for 18.2 would then stop firing with no message
    | at all. A server BANNER is still parsed leniently, because the server writes
    | that one and we only get to cope with it; this you typed on purpose.
    |
    */

    'assume_server_version' => null,

    /*
    |--------------------------------------------------------------------------
    | Capture session guard
    |--------------------------------------------------------------------------
    |
    | Whenever the capture path opens a connection, it bounds its OWN session
    | before the first query: statement_timeout and lock_timeout on PostgreSQL,
    | max_execution_time and innodb_lock_wait_timeout on MySQL. Session scope
    | only — never global, and the tool never takes a lock of its own.
    |
    | This is the second half of "first, do no harm". A lint run may point at a
    | production connection, and a run without a time budget can hold a query or
    | queue behind a lock indefinitely. Even a catalog read gets a budget. The
    | values are milliseconds and must be positive: zero would mean "wait
    | forever", which is the harm this setting exists to prevent.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Catalog reader session
    |--------------------------------------------------------------------------
    |
    | The audit suite reads a LIVE catalog, which on a busy production database
    | is the moment a tool most needs to be harmless. So the reader opens its OWN
    | named connection — the application's is never reconfigured — bounds it
    | before the first query, and makes it read-only.
    |
    | Read-only is VERIFIED, not assumed: the session attempts one write and
    | requires the refusal. A promise about the tool's own behavior that rests on
    | an unverified SET is exactly the silent green this package refuses
    | everywhere else. Measured while building it: the two engines do not enforce
    | read-only the same way, so each driver states its own form.
    |
    | The timeouts are milliseconds and must be positive — zero means "wait
    | forever", which is the harm the setting exists to prevent. idle_in_
    | transaction bounds a read transaction that stalls, which is the shape that
    | holds a snapshot open and blocks VACUUM on PostgreSQL.
    |
    | application_name puts the reader in pg_stat_activity under a name a DBA can
    | recognize at 3am. That is not cosmetic: an unidentified session holding a
    | connection on production is a session someone will kill blind.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Pre-scan
    |--------------------------------------------------------------------------
    |
    | Before a migration is captured, SQLens reads it as text and parses it —
    | it never loads it, because loading a file to inspect it would already run
    | its top-level code. If the pre-scan finds a reason the capture cannot be
    | trusted, the migration is reported as undetermined and is NOT executed.
    |
    | side_effects.additional extends the bundled catalog of surfaces that
    | reach outside the database. Pretend mode intercepts SQL and nothing else,
    | so the PHP around it runs for real: a notification in a migration is
    | actually sent. Add your own surfaces here — a wrapper class, an internal
    | client — written as `Class::method`, `*::method` (any receiver),
    | `function()`, `Class` (any call on it), or `Namespace\*`:
    |
    |     'additional' => ['App\Support\Slack::post', 'App\Integrations\*'],
    |
    | An entry that does not parse is a configuration error naming the key, not
    | an entry that quietly watches nothing — a project that added a surface and
    | saw no finding would read the silence as "we are clean".
    |
    */

    'capture' => [
        'session' => [
            'statement_timeout' => 5000,
            'lock_timeout' => 3000,
        ],

        'prescan' => [
            'side_effects' => [
                'additional' => [],
            ],

            // indirect_calls.allowlist names classes a migration may call into
            // without the pre-scan reporting it. The pre-scan flags a migration
            // that reaches its effect through your own code — `(new Backfill)->run()`,
            // `app(Importer::class)->handle()` — because pretend runs that code for
            // real and cannot see what it does. List a class, or a whole namespace
            // as `App\ValueObjects\*`, that you know is safe:
            //
            //     'allowlist' => ['App\Support\Formatting', 'App\ValueObjects\*'],
            //
            // The framework and pure value classes (Carbon, DateTime, Uuid) are
            // already exempt; this is only for your own code.
            'indirect_calls' => [
                'allowlist' => [],
            ],
        ],

        // The shadow capture mode. Unlike pretend, shadow runs your migrations for
        // REAL against a throwaway database and reads the resulting schema back, so
        // it sees what pretend structurally cannot (result-dependent migrations,
        // runtime errors). It creates and drops a database, so it runs only behind
        // the production guard and only in an allowed environment — never against a
        // production connection. See https://docs.pushery.com/sqlens-for-laravel/capture-modes/.
        'shadow' => [
            // The connection to clone. null uses the run's resolved connection.
            'connection' => null,

            // A direct (non-pooled) connection to provision through. Template and
            // CREATE DATABASE operations break behind a transaction pooler
            // (PgBouncer), so set this to a connection that bypasses one. null lets
            // SQLens use the source connection only when it is provably direct.
            'direct_connection' => null,

            /*
             * How old a leaked shadow database has to be before a later run removes it.
             *
             * The sweep exists for the one cleanup path a try/finally cannot cover: a process
             * killed mid-run — OOM, a pipeline timeout, Ctrl-C — never reaches its own teardown,
             * so what it left behind is dropped by a LATER run instead. On PostgreSQL the more
             * expensive leftover is the TEMPLATE, which carries the whole project schema.
             *
             * The age is what makes that safe when several runs share a server: a worker must
             * never drop the throwaway database another worker is migrating into right now. An
             * hour is far beyond any real run — the shadow timeout below is measured in seconds —
             * and still clears yesterday's leak on the first run of the day.
             *
             * A value BELOW an hour is raised to an hour rather than honored. Lowering it trades a
             * disk-space annoyance for the one mistake this path must never make.
             */
            'orphan_after_seconds' => 3600,

            // The prefix of the throwaway database name. Only [a-z0-9_].
            'database_prefix' => 'sqlens_shadow_',

            // The environments the shadow mode may run in. It refuses to run
            // anywhere else, and the environment check is not overridable by --force.
            'allowed_environments' => ['local', 'testing'],

            // Whether to keep the throwaway database when a run fails, for
            // debugging. Off by default — a database nobody drops is a leak.
            'keep_on_failure' => false,

            // How many seconds the whole shadow provisioning and migration may take.
            // Positive; zero would mean "wait forever", the harm this prevents.
            'timeout' => 120,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | PostgreSQL
    |--------------------------------------------------------------------------
    |
    | PostgreSQL-specific lint settings — the per-engine section, mirrored by a
    | `mysql` section when that driver lands.
    |
    | expected_timeouts: which session timeouts a migration that takes a strong
    | lock is expected to set before it does. PostgreSQL bounds a migration's
    | blast radius with two client settings — 'lock_timeout' caps how long a
    | statement waits in the lock queue (so a blocked DDL cannot pile every later
    | query up behind it) and 'statement_timeout' caps how long it runs. Both are
    | required by default, the strict and safe position; drop one to opt out of
    | that rule. Only these two names are legal — a typo like 'lock_timout' is a
    | misconfiguration error naming the key, never a rule that silently stops
    | firing. It mirrors what SQLens already does to its OWN session
    | (capture.session above): the tool never asks of a migration what it does
    | not do itself.
    |
    | max_locks_per_transaction: how many DISTINCT existing tables a single
    | migration transaction may take a strong lock on before PG.L3.RISKY_OPS_SINGLE_TX
    | flags it. Locks taken in one transaction are all held until it commits, so
    | bundling operations on several tables lengthens the total lock time and grows
    | the queue behind them. The default of 1 flags a transaction that locks more
    | than one table; raise it to allow more, or the rule is dropped by narrowing it.
    | A positive integer — several ALTER clauses in ONE statement are one lock on one
    | table and never count.
    |
    */

    'catalog' => [

        'session' => [
            'statement_timeout' => 5000,
            'lock_timeout' => 1000,
            'idle_in_transaction_timeout' => 5000,
            'application_name' => 'sqlens',
        ],

        // How long a whole catalog reading may take, in milliseconds, before it says so.
        //
        // Distinct from the per-statement timeouts above and not a substitute for
        // them: a hundred fast queries can be inside every per-statement bound and
        // still hold a production connection for half a minute.
        //
        // Exceeding it is a NAMED undetermined, never an abort — the objects already
        // read are worth having, and killing the run would throw them away to report a
        // problem the run itself caused. Five seconds is deliberately generous: this is
        // the coarse upper bound, while the real regression brake is the QUERY COUNT,
        // which is a property of the code rather than of the machine. A wall-clock
        // number tight enough to catch a regression would go red on a loaded laptop and
        // be switched off within a week.
        'budget_ms' => 5000,

        // Which schemas an audit covers. Empty means the session's REAL resolved scope —
        // PostgreSQL's search_path as the server expands it, MySQL's current database —
        // never the assumption that everything lives in `public`. That assumption is what
        // makes an audit quietly miss a project's own tables: a multi-tenant application,
        // or one with a module per schema, keeps almost nothing there.
        //
        //     'schemas' => ['app', 'tenant_42'],
        //
        // Naming schemas is also how multi-tenant scoping stays explicit: a reading never
        // discovers a sibling schema, so an audit cannot widen its own scope onto data it
        // was not pointed at. A schema that does not exist is a configuration error naming
        // it, never an empty audit that reads like a clean run — and the server's own
        // schemas (pg_catalog, information_schema, mysql, …) are refused rather than
        // silently dropped.
        'schemas' => [],

        // The Laravel table prefix, or null to read it from the connection's own
        // `prefix` setting. The override exists for setups that set the prefix at
        // runtime, where the config file does not carry the value the app actually uses.
        //
        // A project with a prefix thinks in terms of `orders`, not `acme_orders` — its
        // migrations say `orders` and a finding about `acme_orders` is about a table the
        // developer does not believe they have. Both names therefore travel: the catalog's
        // own name stays the identity, and the prefix-free logical name rides beside it.
        //
        // A configured prefix that matches NO object is reported as a named skip, never as
        // an empty reading: the likeliest cause is a prefix copied from another project,
        // and an audit of nothing must not read like an audit of a clean schema.
        'table_prefix' => null,

        // What the prefix does to the SCOPE. 'loose' reads everything and marks what is not
        // the project's; 'strict' reads only prefixed objects and names what it left out.
        //
        // Loose is the default deliberately. Of the two ways to be wrong, omitting objects
        // is the worse one: 'strict' would silently drop a project's own unprefixed legacy
        // tables — an audit that misses the tables it exists to examine, reporting clean
        // while doing it. Loose can only be wrong in the visible direction (findings about
        // a co-tenant's tables, each marked as not yours), and noise is recoverable where a
        // silent omission is not. Set 'strict' for a genuinely shared database.
        'prefix_scope' => 'loose',

        // Whether each partition is reported as its own object.
        //
        // Off by default: a partitioned table is ONE object to a rule, and reporting it
        // as n multiplies every finding by the partition count — which makes the first
        // audit of a real database unreadable, and the second one unrun. The partitions
        // are not lost, they become a property of the parent, and a partition that
        // DIFFERS from its siblings is named on the parent as a divergence.
        //
        // Turn it on when you genuinely need per-partition detail; expect the finding
        // count to scale with the number of partitions when you do.
        'report_partitions_individually' => false,

        // Objects a database EXTENSION owns are not the project's own, and judging
        // them is the classic false-positive source: PostGIS alone installs tables
        // whose design nobody here chose. Ownership is read from pg_depend, never
        // from a name list — a list catches the extensions somebody thought of, and
        // catches a user's own `postgis_backup` table by accident. Excluded objects
        // are reported as named skips, so the absence is a stated scope decision.
        // MySQL has no counterpart: an extension there is a server plugin, not an
        // owner of catalog objects, so the setting has no effect on that driver.
        'include_extension_objects' => false,

        'extensions' => [
            // Extensions whose objects ARE this project's business, named one by
            // one. Per-extension rather than one switch, because the two cases are
            // not the same size: a project that manages its own `citext` domains
            // should not have to take PostGIS's tables with it to say so.
            //
            //     'allow' => ['citext'],
            //
            'allow' => [],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Audit
    |--------------------------------------------------------------------------
    |
    | money_columns extends the shipped dictionary of column names that suggest a
    | column holds money. `extra` adds terms and they count as STRONG — a project
    | naming its own column knows what it holds. `ignore` removes terms, from both
    | confidence levels: removing one only from the level it happens to sit in today
    | would mean the ignore silently stops working the day the term is reclassified,
    | and that is the kind of failure nobody connects back to a config file.
    |
    |     'extra' => ['erloes', 'settlement_amount'],
    |     'ignore' => ['rate'],
    |
    | expect states what THIS project wants its servers to be, for the settings where
    | SQLens deliberately has no opinion of its own. lower_case_table_names is the one
    | such setting today: 0 is right on Linux, 2 is what a macOS install gives you, and
    | which of them a project wants depends on where it deploys — so the package ships
    | null and reports drift only against a value somebody actually chose.
    |
    | Leaving it null is the normal state. It silences nothing else: the audit still
    | reports a server whose value cannot support the table names already in the catalog,
    | because that one is objectively provable without any project statement.
    |
    |     'lower_case_table_names' => 0,
    |
    */

    'audit' => [
        /*
        |----------------------------------------------------------------------
        | Ignore list
        |----------------------------------------------------------------------
        |
        | The valve for a grown database, and it is deliberately not a mute
        | button: an ignored finding is still produced, still counted, and still
        | listed under the source that hid it. The header says how many. A run
        | that hid twelve findings can therefore never read as "clean".
        |
        | Three forms, least precise first:
        |
        |   'rules'   silences a rule everywhere. Blunt, and honest about it.
        |   'objects' silences every rule on a path. For a legacy schema nobody
        |             is going to fix.
        |   'pairs'   silences ONE rule on named paths. Reach for this one: the
        |             other two grow by themselves. A rule ignored project-wide
        |             keeps ignoring itself on tables added next year, and a
        |             schema ignored wholesale hides rules that did not exist
        |             when the line was written.
        |
        | A path is dot-separated and increasingly specific -- schema,
        | schema.table, schema.table.column -- and a segment may end in '*' to
        | match a prefix within THAT segment. The glob never crosses a dot, so a
        | pattern's reach is readable: 'public.orders' cannot touch
        | 'public.orders_archive'. A pattern covers what is INSIDE what it names
        | (a table's columns) but never what CONTAINS it (its schema).
        |
        | If the application has a table prefix, write the name either way --
        | both 'public.orders' and 'public.wp_orders' match.
        |
        */
        'ignore' => [
            'rules' => [],
            'objects' => [],
            'pairs' => [],
        ],

        /*
        |----------------------------------------------------------------------
        | Tenancy
        |----------------------------------------------------------------------
        |
        | "Audit the database" stops being one statement the moment there is
        | more than one tenant database. A report produced from whichever
        | connection happened to be default describes ONE tenant, and it looks
        | exactly like a report about the application -- same header, same
        | findings, same exit code. The reader then draws a conclusion about
        | their system from a statement about one of their customers.
        |
        | SQLens does not resolve that quietly. When it sees signs of a tenant
        | setup it asks you to say which tenant the report is about, and prints
        | that in the header.
        |
        |   'none'      this project has one database. The default.
        |   'explicit'  it has tenants; 'reference' names the one to audit, and
        |               the report says the finding applies to that tenant only.
        |
        | There is deliberately no fan-out: no --all-tenants, no loop over
        | tenant connections, no merged report. An aggregate over tenants is a
        | different kind of claim -- it would have to say which tenants
        | disagreed and why -- and a loop without that produces a report nobody
        | can act on. Tenant-drift is a later release, and this is the boundary
        | named rather than an excuse.
        |
        */
        'tenancy' => [
            'mode' => 'none',
            'reference' => null,
        ],

        /*
         * Who generates a UUID primary key: 'app', 'server', or null.
         *
         * Null is the honest default. A UUID column with no server-side default tells the audit
         * nothing on its own — Laravel generates UUIDs in the application, so the absence is the
         * normal case rather than a signal — and a recommendation resting on a guess about code
         * the tool never reads would be advice nobody asked for. Say which side it is and the
         * recommendation becomes answerable.
         */
        'uuid_generated_by' => null,

        'money_columns' => [
            'extra' => [],
            'ignore' => [],
        ],

        /*
        |----------------------------------------------------------------------
        | unused_index
        |----------------------------------------------------------------------
        |
        | How long the server must have been counting before "this index has
        | never been scanned" is evidence rather than an artifact of a recent
        | statistics reset. The rule that reads it is experimental and opt-in;
        | this value only decides how patient it is once you have enabled it.
        |
        | Thirty days by default: long enough to cover a monthly report nobody
        | runs more often, which is the query most likely to be the sole reader
        | of an index that otherwise looks dead.
        |
        */
        'unused_index' => [
            'min_observation_days' => 30,
        ],

        'expect' => [
            'lower_case_table_names' => null,
        ],

        /*
        |----------------------------------------------------------------------
        | Identifier naming
        |----------------------------------------------------------------------
        |
        | The shape an identifier must have for the level-8 naming rule. The
        | default is snake_case with no leading digit -- not a house style, but
        | the shape that means the SAME THING on both engines unquoted: PostgreSQL
        | folds an unquoted identifier to lower case, MySQL does not, and
        | `2fa_secret` is a syntax error unquoted on PostgreSQL.
        |
        | A pattern PCRE cannot compile is refused when the configuration is
        | validated, before anything runs. That is deliberate: `preg_match()`
        | answers `false` rather than `0` for a broken pattern, so a typo here
        | would otherwise report every identifier in the database as a violation
        | and nothing in the report would point at this line.
        |
        | `exempt` names identifiers this rule does not judge at all -- for a
        | schema somebody else owns, where the convention is not yours to set.
        | Each entry is a PCRE pattern and is matched against the BARE name.
        |
        */
        'naming' => [
            'pattern' => '/^[a-z][a-z0-9_]*$/',
            'exempt' => [],
            // What a single-column foreign key's column is expected to end with. An EMPTY value is
            // refused and the default used instead: every name ends with the empty string, so an
            // empty setting would silence the rule completely -- and "no findings" would read as
            // "my keys are named the way I asked" when nothing had been asked.
            'foreign_key_suffix' => '_id',
        ],

        /*
         * Comment requirements -- OFF by default, and that is the whole design.
         *
         * `PG.L9.DOC_MISSING_COMMENT` and its MySQL twin are the most opinionated checks in the
         * catalog. Level 9 is already an opt-in, and this is a second one on top: a project that
         * raised its level to see the pedantic band should not be told, in the same breath, that
         * every table it owns is undocumented.
         *
         * `columns` is separate from `tables` because they are different amounts of work. A team
         * that documents its tables has done something useful; requiring the same of every column
         * is a decision of its own, and folding the two into one switch would make the cheaper half
         * unreachable.
         *
         * `exempt` REPLACES the shipped framework list rather than adding to it, so a project that
         * names its own set is not silently still carrying ours. The shipped default is
         * MissingComment::FRAMEWORK_TABLES -- `migrations`, `jobs`, `cache`, `sessions` and the
         * rest, matched as WHOLE names: a project's own `job_applications` is not the framework's
         * `jobs`, and a prefix match would exempt it.
         */
        'documentation' => [
            'require_table_comments' => false,
            'require_column_comments' => false,
            'exempt' => null,
        ],
    ],

    'pgsql' => [
        'expected_timeouts' => ['lock_timeout', 'statement_timeout'],
        'max_locks_per_transaction' => 1,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security
    |--------------------------------------------------------------------------
    |
    | The security severity axis. Security and privacy findings are gated by
    | severity — 'info', 'low', 'medium', 'high', 'critical' — independent of
    | the strictness level, so a level-0 run still breaks on a critical finding.
    | That independence is the point: levels model how pedantic a project wants
    | SQLens to be, and risk is not a matter of appetite. A password literal in a
    | migration is critical whether or not the project has got round to level 5 —
    | and measured against the level it would be invisible in exactly the projects
    | most likely to have it, because a project early in its adoption runs a low
    | level.
    |
    | min_severity is the floor: a finding at or above it fails the run. The
    | shipped default is 'high', so a high or critical security finding blocks out
    | of the box and an info/low/medium one is reported without blocking.
    |
    | 'none' means REPORT, NEVER BLOCK. It is spelled as a word rather than left
    | as null on purpose: null reads as "unset", and "did you decide this or forget
    | it?" is the ambiguity this key exists to remove. So null is refused with a
    | message naming 'none' — say what you mean, and the report says it back.
    | 'none' does not silence anything: the findings still appear, in the output
    | and in every count. It only stops them deciding the exit code.
    |
    */

    'security' => [

        /*
         * The connection the security readers examine, by NAME — never credentials.
         *
         * Null means the run's own connection, which is the shipped state and right for most
         * projects. Naming one here is for the case the suite was built for: a least-privilege role
         * that may read `pg_authid`, `pg_hba_file_rules` and the server settings, without giving
         * those rights to the role that serves requests.
         *
         * `--connection` on the command line wins over this, because a run somebody typed is a
         * decision about THAT run. Whichever wins, the report names it: on a read/write split a
         * replica answers with different variables, so which instance was examined is a statement
         * rather than a detail.
         *
         * A name no `config/database.php` defines is a MISCONFIGURATION, not a fall back to the
         * default. Falling back would examine the wrong instance and report it as clean.
         *
         * Named `audit_connection` rather than `connection` on purpose: `runtime_connection` and
         * `migration_connection` beside it name connections this suite ANALYSES — the read/write
         * split it reasons about. This one is the connection the readers RUN ON. Three keys ending
         * in `connection` where one means something else would be read wrong exactly once, by
         * somebody wiring a least-privilege role at the end of a day.
         */
        'audit_connection' => null,
        'min_severity' => 'high',

        /*
         * Whether a migration that ships INSIDE a package counts as one of yours.
         *
         * Laravel runs package migrations — a package registers them with `loadMigrationsFrom()`
         * and they execute against your database like any other. So they are migrations, and this
         * switch is not about what they are but about whether you can act on them.
         *
         * Off by default, because you usually cannot. A Critical inside `vendor/` is a finding
         * whose only available fix is "open an issue upstream", repeated on every run — and a rule
         * that cannot be acted on is one people silence wholesale, taking the findings they COULD
         * have acted on with it.
         *
         * Turn it on when the question is genuinely about the dependency tree: an audit that has to
         * state what everything running against this database does, not just what your own team
         * wrote. Expect findings you cannot fix, and read them as inventory rather than as a backlog.
         *
         * ## It decides two things, and it used to decide only one
         *
         * Off, a run does not ENUMERATE a package's migrations at all — the file is never loaded and
         * never pretend-executed. On, it does, and the classifier then binds it as a migration of
         * yours so the rules that ask about provenance treat it like one.
         *
         * The second half is what this setting always did. The first was missing, and the gap was
         * user-facing: a package's migration was still read and still able to produce a
         * capture-layer finding, so a first run after `composer require` could fail on findings
         * inside somebody else's package while reporting nothing about the project's own. The
         * argument above is the one that closes it — it is the same argument, applied one step
         * earlier.
         *
         * ## Two runs are deliberately not filtered
         *
         * A run whose paths were NAMED — `--path`, `sqlens.migration_paths`, or `--file` — sees
         * everything under them. Naming a path is a person saying "these", and quietly dropping
         * part of what they named would make the argument advisory.
         *
         * And `sqlens:predeploy` always includes them, whatever this says. A package's migration
         * runs during a deploy and can take a lock like any other, so a preflight that could not see
         * it would answer its own question wrongly.
         */
        'include_vendor_migrations' => false,

        /*
         * Where the end-of-life data comes from, when it should not come from the copy this
         * package ships.
         *
         * The patch-currency check compares the server's version against release and end-of-life
         * dates, and it reads them from a FILE rather than from the network -- deliberately, because
         * a check that needed egress would be unusable on a CI runner without it and would answer
         * the same question differently on two days.
         *
         * Three files can answer, in this order: this key, then the copy an application published
         * into its own resources/data/eol.json, then the copy bundled with the package. The one that
         * actually answered is named in the run header, so a refresh that landed somewhere nothing
         * reads is visible rather than silent.
         *
         * Absolute, unlike baseline.path: a refresh may write outside the repository entirely, and
         * forcing this repo-relative would push a generated file into version control.
         */
        'advisories' => [
            'path' => env('SQLENS_ADVISORIES_PATH'),

            /*
             * Where `sqlens:security --refresh-advisories` fetches from, and why nothing is here.
             *
             * There is no default on purpose. Shipping an endpoint would be this package accepting
             * somebody else's terms of use -- their license, their rate limit, their attribution --
             * on behalf of every consumer, and none of those are ours to agree to for you.
             *
             * The URL must serve a document in this package's OWN advisory format. That is what
             * keeps the package from ever parsing a third party's shape, so it never inherits a
             * change to that shape; generate the file from whatever source your own terms allow.
             *
             * https only. A baseline fetched over plain http can be answered by anybody on the path
             * with a file this package then trusts, which is the one artifact where being lied to
             * costs the most.
             */
            'source' => env('SQLENS_ADVISORIES_SOURCE'),
        ],

        /*
         * The two connections a least-privilege setup keeps apart, and the single most effective
         * measure this package can check for. The runtime connection is what the application serves
         * requests with; the migration connection is what deploys schema changes. When they are the
         * same role, every SQL injection that reaches the database reaches it with DDL rights — and
         * a dropped table is a very different incident from a leaked row.
         *
         * Leave both null when the application genuinely runs on one connection. That is a real
         * answer rather than a missing one: SQLens then reports the state as a finding instead of
         * guessing which of your connections was meant to be the safe one.
         *
         * https://docs.pushery.com/sqlens-for-laravel/rules/sec-priv-runtime-ddl/
         */
        'runtime_connection' => null,
        'migration_connection' => null,

        /*
         * The injection half, which lives in a PHPStan extension rather than in this package's own
         * engine — because its subject is PHP source and a second static analyzer would be a second
         * opinion about the same code.
         *
         * `mode` is `off` by default, and `off` is a real answer rather than an omission: a project
         * that has not wired this is not a project free of raw SQL, it is one nobody looked at. The
         * run says so, with the reason, instead of returning an empty list that reads like a clean
         * bill of health.
         *
         * `read` takes a result PHPStan has already written. That is the ordinary shape in CI, where
         * PHPStan runs as its own step and both steps share a workspace:
         *
         *     vendor/bin/phpstan analyse --error-format=json > build/phpstan.json
         *     php artisan sqlens:security
         *
         * The path is repository-relative like every other path here; an absolute one is accepted
         * too, because a CI step that knows its own workspace should not have to compute a way back
         * to it. Diagnostics whose identifier belongs to no SQLens analyse rule are dropped — a
         * project runs PHPStan for its own reasons, and its own errors are not this suite's to relay.
         */
        'analyse' => [
            'mode' => env('SQLENS_ANALYSE_MODE', 'off'),
            'result_path' => env('SQLENS_ANALYSE_RESULT_PATH'),
        ],

        /*
         * Row-level security: which tables SQLens should hold to it.
         *
         * "Which tables carry tenant data" is a question only this application can answer. Checking
         * every table would produce a finding for every reference table, every job queue and every
         * migration ledger — a report nobody finishes, from a tool that has learned nothing about the
         * application. So nothing is guessed:
         *
         *   listed     only the tables named below (the default)
         *   heuristic  every table carrying `tenant_column`
         *   off        no RLS checks at all
         *
         * With `listed` and an empty list, SQLens reports ONE undetermined naming this key — not a
         * silent pass, and not a hundred findings. `off` is an ANSWER to that: the run then reports
         * that this database separates nothing, which is a different line from never having been
         * asked.
         *
         * A name may be written either way. `orders` resolves through `current_schema()`, exactly
         * where an unqualified CREATE TABLE puts a table, so the name your migration used is the name
         * that works here; `reporting.orders` reaches a table in another schema.
         *
         *     'tables' => ['orders', 'invoices', 'reporting.orders_archive'],
         *
         * https://docs.pushery.com/sqlens-for-laravel/rules/sec-rls-disabled/
         */
        'rls' => [
            'mode' => 'listed',
            'tables' => [],
            'tenant_column' => 'tenant_id',
        ],

        /*
        | The privacy pack — OFF, and off is the decision rather than the default nobody
        | got round to changing.
        |
        | These rules read column NAMES and guess what lives in them. That is a useful guess
        | and an unreliable one: a column called `iban` usually holds an IBAN, and sometimes
        | holds a label. A pack that guessed wrong by default would teach a team to ignore
        | the category it guessed in, which costs more than the findings are worth.
        |
        | Switched off, the rules are not registered at all. They cost no query, no scan and
        | no time — the run does not carry them and quietly skip them, it does not have them.
        | What it DOES carry is the fact that the category is inactive, in the reproducibility
        | header: a suite that checked less has to say so.
        */
        'privacy' => [
            'enabled' => false,

            /*
             * A dictionary of your own, replacing the bundled one. Repository-relative, like
             * every other path this package accepts: an absolute path pins a configuration to
             * one machine, and a config file that only works where it was written is a config
             * file somebody will edit on the next machine.
             */
            'dictionary' => null,

            /*
             * Terms to ADD to whichever dictionary is in force. The common case is a domain
             * word the bundled list cannot know — an insurance number, a national identifier,
             * whatever your industry calls the thing it must not leak.
             */
            'extra_terms' => [],

            /*
             * Columns this project has looked at and decided about. Qualified names, because
             * `notes` is a different question on `orders` than on `patients` — an unqualified
             * exclusion would silence a column somebody never considered.
             */
            'ignore_columns' => [],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Preflight
    |--------------------------------------------------------------------------
    |
    | The connection a predeploy reading uses, by NAME — never credentials. A
    | password in a package config is a password in a repository, and a
    | read-only role's is still one.
    |
    | It exists because the connection nearest to hand at deploy time is the one
    | that runs your migrations, and that role holds ALTER and DROP on your
    | schema. Reading through it works perfectly and quietly costs the
    | least-privilege promise this package makes about itself — everything stays
    | green, which is exactly why it needs saying out loud.
    |
    | Left null, the reading falls back to `connection` above and then stops. It
    | never falls through to the application's default: that is the silent use of
    | the migration connection this setting exists to prevent.
    |
    | On a project with one connection, naming it here is fine — the run then
    | reports that it read with migration rights rather than pretending
    | otherwise.
    |
    | https://docs.pushery.com/sqlens-for-laravel/deploy-readers/
    |
    */

    /*
    | budget_ms bounds the WHOLE `sqlens:predeploy` run, not one reading. When it
    | runs out, the checks that were not reached are reported `undetermined` with
    | the budget named — never dropped, because a gate that quietly ran four of
    | its nine checks and reported clean is trusted like a complete one and is
    | worth nothing.
    |
    | It is a promise rather than a preference: a gate that visibly delays a
    | deploy gets configured away in the first sprint, and a gate nobody runs has
    | helped nobody. `--budget` overrides it for a single run.
    */

    'preflight' => [
        'connection' => null,
        'budget_ms' => 5000,

        /*
         * How long a session must have been running before the preflight treats it as something a
         * deploy could collide with, in milliseconds.
         *
         * The default is deliberately LOW. A transaction open for five seconds is unremarkable at
         * noon and is exactly the thing to know about in the minute before a migration: an ALTER
         * queues behind it, and every read arriving after the ALTER queues too.
         *
         * Raise it on an instance where long reads are normal — a reporting replica, an analytics
         * schema, a nightly export. That is a real answer to a real false positive, and it is why
         * this is a setting rather than a constant: the alternative a project reaches for otherwise
         * is switching the check off, which takes the genuine blockers with it.
         *
         * Zero and negative are refused rather than read as "report everything": a preflight that
         * listed every session on a busy server would be read once.
         */
        'long_running_ms' => 5000,

        /*
         * The replica lag at which the preflight reports, in milliseconds.
         *
         * A deploy with heavy DDL on an already-lagging replica widens the gap further, and read
         * replicas then serve stale data for minutes. Ten seconds is the shipped answer to "far
         * enough behind that adding to it is a decision".
         *
         * Measured against `replay_lag`, so it is the time axis rather than the byte one. The two
         * disagree on purpose and both are reported: a quiet primary keeps `replay_lag` small
         * however much WAL is outstanding.
         */
        'replication_lag_ms' => 10000,

        /*
         * How large an object has to be before a deploy finding about it is rated higher.
         *
         * Empty by default, which means the shipped table in `resources/data/escalation-thresholds.json`
         * decides. Set an operation here to replace ITS steps entirely — `rewrite`, `index_build`,
         * `constraint_validation` and `backfill` are the four the artefact defines, and naming one it
         * does not know is REFUSED rather than ignored, because a typo would otherwise mean the
         * escalation somebody configured silently never happens.
         *
         * A step is `['min_rows' => 1000000, 'raise_to' => 'high']` (or `min_bytes` for `rewrite`,
         * which scales with size on disk rather than with row count). Steps are read in the order
         * given, and the largest one that fits wins.
         *
         * These numbers only ever RAISE a severity, and they can neither create a finding nor remove
         * one. That is not a limitation but the reason the mechanism is safe: a row estimate depends
         * on when ANALYZE last ran, and a number that could silence a finding would make the same
         * migration pass on Monday and fail on Friday with nothing having changed but a statistics
         * refresh.
         */
        'thresholds' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Deploy
    |--------------------------------------------------------------------------
    |
    | debt.path is where the migration debt account lives — a repository FILE,
    | never a database table. A debt outlives the run that found it, so it has to
    | be recorded somewhere, and the one place this package will not write is the
    | database it is watching: a table would need a migration, a write privilege
    | and a schema of its own on the very instance whose safety is the point.
    |
    | In Git it reviews like code. The diff shows what a change to a migration
    | actually cost, and the history says who accepted it and when.
    |
    | Repository-relative, and never null: unlike a baseline, which a project may
    | genuinely not have, the ledger always has a location — null would only be a
    | second way of spelling "do not record", which is what an empty file already
    | says out loud.
    |
    */

    'deploy' => [

        'drift' => [
            /*
             * Whether `sqlens:drift` reports or blocks.
             *
             * `report` is the shipped state, and it is a survival decision rather than a soft one.
             * The first drift run on a database that has been in production for years finds a
             * decade of hand-made objects — and a gate that turns red there is not adopted, it is
             * switched off. After that nothing is reported at all, which is strictly worse than a
             * green exit somebody read.
             *
             * The documented path is report first, then the exclude file for the differences that
             * are intentional, and only then `gate`. Raising it is a deliberate project decision,
             * and it can also be made per run with --fail-on-drift.
             *
             * Anything that is not literally `gate` is report, including a typo: erring toward
             * blocking on a value nobody can read would put a project into a mode it never asked
             * for.
             */
            'mode' => 'report',

            /*
             * Where the differences this project has accepted are written down.
             *
             * The second step of the documented path: report first, then record the differences that
             * are deliberate — the reporting view somebody made by hand, the index a foreign system
             * owns, the column that grew there historically — and only then raise the mode to `gate`.
             * Without this step the way from reporting to blocking is not walkable, because the first
             * gate run on a grown database is red for reasons nobody caused today.
             *
             * A REPOSITORY file, never a database table. A decision about a schema belongs where
             * decisions are reviewed: in a pull request, with an author and a date, and with its
             * removal as visible as its addition. SQLens writes to no database at all.
             *
             * Every entry carries a mandatory `reason`. An exclusion that does not say why it exists
             * cannot be reviewed — six months on, nobody can tell a decision from a silenced finding
             * — so a missing reason ends the run rather than defaulting to something.
             *
             * An entry that matches nothing also ends the run. Excludes nobody prunes grow into a
             * ceiling under which real drift disappears, and the growth is invisible: forty stale
             * lines look exactly like four that are still true.
             *
             * `sqlens:drift --update-excludes` writes the file from a run's own findings, with a placeholder
             * reason the next run refuses, so the obligation cannot be committed and forgotten. A missing file simply means nothing is accepted yet —
             * which is every project's first run, and not an error.
             *
             * REPOSITORY-RELATIVE, like the debt account's path and for the same reason: an absolute
             * path would let the decision log live outside the repository, where its changes are
             * reviewed by nobody. `--exclude-file=` overrides it for one run and is taken as given.
             */
            'exclude_file' => 'sqlens-drift-excludes.json',
        ],

        'debt' => [
            /*
             * Whether the debt account is consulted at all.
             *
             * OFF by default, because adopting the account is a decision and a package that shipped
             * it switched on would make that decision for every project that installs it. The
             * visible cost of the other default is what settled it: `sqlens:audit` reports a
             * MISSING account rather than an empty one — that distinction is the point on a deploy
             * server, where a file that did not ship looks exactly like a project with no debts —
             * so shipping it enabled would tell every project that never adopted it about a file it
             * never created, on every run.
             *
             * Turn it on, then `sqlens:lint --debt=record` once, and the account exists.
             *
             * It is NOT a way to silence a debt somebody would rather not see. That is what the
             * acknowledged state with a written reason is for, and the difference is that one of
             * them is visible in the file.
             */
            'enabled' => false,

            'path' => 'sqlens-debt.json',

            /*
             * At what age an outstanding debt gets louder, in UTC calendar days.
             *
             * A band only ever RAISES a finding's severity — it never creates one, never removes
             * one, and never changes a rule id. The debt reported on day 1 and the debt reported on
             * day 400 are the same finding about the same object; the older one is simply harder to
             * keep ignoring. Whether an age BREAKS the run is a separate setting, because "tell me
             * loudly but do not stop the deploy at 3am" is what most projects actually want.
             *
             * Overriding one band leaves the other two on the shipped numbers.
             */
            'thresholds' => [
                'notice' => 30,
                'warning' => 90,
                'error' => 180,
            ],

            /*
             * The age at which an outstanding debt BREAKS a deploy, in UTC calendar days.
             *
             * Null — the default — means never. Debts are a reported state, not a gate: the safe
             * two-step patterns leave them on purpose, and a deploy command that refused to finish
             * over one would punish the projects doing the right thing.
             *
             * Set it when the account has become something the team actually acts on, and set it
             * to a number nobody crosses by accident. It is deliberately separate from the bands
             * above: escalating a severity and stopping a deploy at 3am are different decisions,
             * and a project that wants the first without the second is the ordinary case.
             *
             * An ACKNOWLEDGED debt never breaks a run, whatever its age. The decision to carry it
             * has already been made and written down; overriding that from a config value would
             * make the acknowledgment worthless.
             */
            'fail_at' => null,
        ],

        /*
         * The predeploy gate's one escape hatch, as a project-wide setting.
         *
         * The gate is fail-closed: a check that could not answer blocks the deploy, because the
         * `migrate` step behind it would have failed on the same unreachable database anyway, and
         * a gate that waves through what it could not read is worth nothing.
         *
         * `--allow-undetermined` is the per-run way out. This is the same decision taken once, for
         * a project whose deploy pipeline genuinely cannot depend on the gate — and it is `false`
         * here because a hatch nobody remembers opening is the failure mode worth designing
         * against.
         *
         * Either way the waiver is on the RECORD: the report's run header carries
         * `undetermined_waiver`, so a green that was waved through can never be read as an earned
         * one. A real finding still blocks whatever this says — the hatch is one door.
         */
        'predeploy' => [
            'allow_undetermined' => false,

            /*
             * How much free disk the operator says this instance has, in BYTES — or null.
             *
             * The disk-headroom check estimates how much space a pending rewrite needs and holds it
             * against what the instance reports as free. On most instances that second half is
             * unanswerable: free filesystem space is not visible from inside the database at all,
             * and on a managed database it never will be, whatever privileges are granted. The
             * check then reports `undetermined` with the estimate attached, forever.
             *
             * This key is the deliberate way out. Set it and the comparison happens.
             *
             * ⚠️ It is a CLAIM, not a reading, and the finding says so. Nothing here can verify it,
             * and a stale value is worse than none: an operator who set it once when the volume was
             * new has told the gate that a full disk is empty. Feed it from the same monitoring you
             * would have checked by hand, or leave it null and read the estimate.
             *
             * Null is the shipped state, and null means "ask the instance" rather than "assume
             * plenty" — the check stays undetermined rather than passing.
             */
            'available_disk_bytes' => null,
        ],

        /*
         * What the run after `migrate --force` looks for beyond the two it always checks.
         */
        'postdeploy' => [
            /*
             * The whole `sqlens:postdeploy` run's time budget, in MILLISECONDS.
             *
             * A run that hangs off the end of every deploy has one survival condition: it must not
             * be something people wait for. A gate that visibly delays a deploy gets configured
             * away in the first sprint, and a gate nobody runs has helped nobody -- so the number
             * is held by a test (`tests/Performance/PostdeployBudgetTest.php`) rather than by an
             * intention.
             *
             * ⚠️ Milliseconds, matching `preflight.budget_ms` and the `--budget` flag on both
             * commands. Two sibling gates measuring the same thing in different units is a reader
             * getting it wrong by a factor of a thousand, in the direction that looks like it
             * worked.
             *
             * ⚠️ This key exists because postdeploy used to read `preflight.budget_ms` -- the
             * PREDEPLOY budget. Raising the pre-deploy gate's allowance silently raised the
             * aftercare's too, and lowering it silently squeezed a run that had nothing to do with
             * the change. Two commands, two promises, two numbers.
             *
             * Exceeding it is a FINDING (`DEPLOY.RUN.TIME_BUDGET_EXCEEDED`), never an abort. The
             * run finishes and reports the measured duration and the most expensive check, because
             * a budget that breaks tells you the run is too slow and stopping early would destroy
             * the only information that says what to fix. `--budget` overrides it for a single run.
             */
            'budget_ms' => 5000,

            /*
             * The name shapes an unfinished expand/contract migration leaves behind.
             *
             * PCRE patterns against the BARE object name, and every shipped one is anchored:
             * `/_old$/` matches `users_old` and not `threshold_settings`. Replacing this list
             * replaces it wholly — a project with its own convention should say what that is
             * rather than inherit ours alongside it.
             *
             * A pattern PCRE cannot compile is dropped rather than allowed to throw, and a list
             * that ends up empty falls back to the shipped one: an empty list would silence the
             * check completely, and "no findings" would read as "nothing left behind".
             *
             * ⚠️ A match here is NEVER a failure. A name is not evidence -- `orders_old` is what
             * an abandoned rename leaves behind and what a team calls the archive it queries
             * every quarter, and the catalog holds nothing that separates them. Every match is
             * reported as `undetermined` with that reason named.
             */
            'transition_patterns' => null,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Agent layer — the MCP server
    |--------------------------------------------------------------------------
    |
    | SQLens can expose itself to an AI coding agent over the Model Context
    | Protocol, so the agent can ask a deterministic tool what a migration will
    | do instead of guessing. The server is a thin shell over the same commands:
    | it adds no logic and takes no rights of its own.
    |
    | The surface is an ATTACK SURFACE, so the shipped state is the safe one.
    | Every read-only tool is on, every mutating tool is off, and turning one on
    | is a separate, visible decision per tool — there is no master switch. There
    | is no free-text SQL tool and there never will be.
    |
    | See https://docs.pushery.com/sqlens-for-laravel/mcp-server/.
    |
    */

    'agent' => [

        'mcp' => [

            /*
             * The transport. `stdio` is the only value v1 accepts.
             *
             * An HTTP server is a team-shared endpoint and needs an authentication story of its
             * own; stdio inherits the trust boundary of the process that started it, which is the
             * agent already running on the developer's machine. The setting exists so the day HTTP
             * arrives it is a value here rather than a new shape.
             */
            'transport' => 'stdio',

            /*
             * The Laravel connection the tools run against. Null uses the application's default.
             *
             * The same connection the CLI would use, deliberately: a server that could point
             * somewhere else would be a second answer about a different database, reachable
             * without anybody noticing which one they asked.
             */
            'connection' => null,

            /*
             * Where `get_findings` reads the last report from — repository-relative.
             *
             * It READS an artifact a previous run wrote; it never runs the checks again. An agent
             * asking "what did the last run find" must not be able to start a database run by
             * asking, and a second run would answer about a different moment anyway.
             */
            'findings_path' => 'sqlens-report.json',

            /*
             * The hard ceiling on findings in one answer.
             *
             * A run with four thousand findings would fill an agent's whole context window with
             * one tool call and leave no room for the work. Crossing the ceiling is REPORTED as
             * crossing it — never a quiet truncation, which reads exactly like a database with
             * fewer problems than it has.
             */
            'max_findings' => 200,

            /*
             * Which tools the server exposes. A name that is not listed here is not a tool.
             *
             * The four read-only tools are on: they read, they never write, and they are the
             * point of the server. The mutating ones are off, and each is enabled on its own —
             * `lint_shadow` creates and drops a database, `predeploy` gates a deploy. A project
             * that wants one of those says so about THAT one.
             *
             * A tool this build does not know is a configuration error naming the ones it does,
             * never a silent no-op: a typo that quietly enables nothing looks exactly like a
             * setting that worked.
             */
            /*
             * The standing "yes, I mean it" for a shadow run started over the protocol.
             *
             * A shadow run creates and drops a throwaway database, and the CLI asks before it does
             * — interactively, or with --force. An MCP server has no terminal and nobody to ask, so
             * over the protocol there is no prompt at all: without this set, `lint_shadow` answers
             * `undetermined` with the reason and points at the CLI. Silence is never taken as yes.
             *
             * It is deliberately SEPARATE from enabling the tool. Enabling says an agent may ask;
             * this says a run may actually happen. Two switches, because they are two decisions.
             *
             * It is also the weakest thing the guard can be told. It never overrides the allowed
             * environment list, and it never lets a run reach a connection that looks like
             * production — both refuse regardless. What it grants is the confirmation, inside an
             * environment somebody already restricted.
             */
            'shadow_consent' => false,

            'tools' => [
                'lint_pending' => true,
                'explain_rule' => true,
                'get_findings' => true,
                'get_debt_ledger' => true,
                'lint_shadow' => false,
                'predeploy' => false,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Reporting
    |--------------------------------------------------------------------------
    |
    | default_format names the reporter used when no --format is given:
    | 'console' or 'json'. An unknown format — here or on the command line — is
    | a hard error naming every available format, never a fallback.
    |
    */

    'reporting' => [
        'default_format' => 'console',

        /*
         * Whether a blocking or rewrite finding carries its maintenance-window advice — the
         * sentence that says what kind of precaution the operation needs.
         *
         * It never estimates a duration. How long a rewrite takes depends on the row count, the
         * hardware and the concurrent load, none of which a static run has seen, and a guessed
         * number would look like knowledge while being a guess — the reader plans against it and
         * the plan fails at exactly the moment the window matters. Concrete time and size
         * statements are the deploy suite's, which reads real statistics.
         *
         * Turn it off once the advice is second nature to the team: it is the same sentence every
         * time, which is what makes it trustworthy and eventually what makes it skippable.
         * See https://docs.pushery.com/sqlens-for-laravel/lint/
         */
        'maintenance_window' => true,

        'sarif' => [
            /*
             * Which repository file a live-database alert is anchored to in the SARIF report.
             *
             * Most of what this package finds is not in your repository: a table, a role, a grant, a
             * server variable. SARIF still needs a physical location for GitHub to attach an alert
             * to, and the two obvious answers are both wrong — omit it and the alert lands on the
             * repository root, invent a file and a line and it looks like a finding about unrelated
             * code.
             *
             * So the report carries the real subject as a SARIF `logicalLocation` and anchors the
             * alert here. The default is this config file because it is what a reader would open in
             * response; point it somewhere your team already watches if that fits better. The
             * message always names the object first and says the file is a stand-in, so the anchor
             * never reads as the subject.
             *
             * Repository-relative — an absolute path from the machine that produced the report
             * matches nothing in the repository GitHub resolves it against.
             * See https://docs.pushery.com/sqlens-for-laravel/contracts/
             */
            'anchor_file' => 'config/sqlens.php',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline
    |--------------------------------------------------------------------------
    |
    | Where the accepted-findings ledger lives, as a repo-relative file path.
    | The ledger is a repo FILE, never a database table (the tool writes no
    | database state), and the path stays relative so the config is portable
    | across machines. `null` means no baseline is applied.
    |
    | stale: what an entry that matched nothing in a run costs. A baseline nobody
    | prunes grows shut — entries pile up for findings fixed months ago and the
    | file stops describing what the project accepts — so a stale entry is ALWAYS
    | named. 'report' leaves the run's verdict alone (the default, because a fresh
    | baseline on a moving codebase would otherwise fail constantly); 'error'
    | treats the baseline as misconfigured.
    |
    */

    'baseline' => [
        'path' => null,
        'stale' => 'report',
    ],

    /*
    |--------------------------------------------------------------------------
    | Suppression
    |--------------------------------------------------------------------------
    |
    | allow_undetermined names the reasons a suppression may hide. It is empty by
    | design: an `undetermined` means a check could not RUN, which is not a
    | finding anyone accepted, and hiding it would hide that it never ran. Listing
    | a reason here is a project saying, explicitly and per reason, that it can
    | live without that check — and every suppression granted this way is marked
    | as such wherever it is shown, so it never looks like an ordinary one.
    |
    |     'allow_undetermined' => ['missing_external_tool'],
    |
    */

    'suppression' => [
        'allow_undetermined' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Ignore
    |--------------------------------------------------------------------------
    |
    | Project-wide suppressions. Each entry names the rule it suppresses and —
    | mandatory — the reason why, so every suppression is a documented decision:
    |
    |     [
    |         'rule' => 'PG.L2.NAME',        // required: the rule id
    |         'reason' => 'why it is off',   // required: the documented reason
    |         'paths' => ['db/legacy/*'],    // optional: repo-relative globs
    |         'suites' => ['lint'],          // optional: limit to these suites
    |     ],
    |
    | An ignore entry with an unknown rule id or one that never matches in a
    | run is reported — a suppression that silently does nothing is a bug in
    | your config, and this tool says so.
    |
    */

    'ignore' => [],

    /*
    |--------------------------------------------------------------------------
    | Suites (placeholder — not yet active)
    |--------------------------------------------------------------------------
    |
    | Which of the suites run — lint, audit, analyse, format, guard, deploy,
    | agent. Not active yet; the semantics arrive with the lint core.
    |
    | 'suites' => ['lint', 'audit'],
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Profiles
    |--------------------------------------------------------------------------
    |
    | Named environment profiles. A profile is a PARTIAL OVERRIDE of the settings
    | above, written in exactly the same shape — so there is one vocabulary, not a
    | second one for profiles. Name only what the environment changes; anything a
    | profile leaves out keeps its value from above.
    |
    | The precedence is fixed and reported in the run header: base config, then
    | the active profile, then the command-line flag. The flag always wins, so a
    | one-off `--level=6` is never overruled by a profile.
    |
    | The active profile is the `profile` key above (and, per run, --profile).
    | The three names are the ones SQLens knows: a typo like 'stagng' is a
    | misconfiguration naming the legal set, never a silent fall back to local —
    | a lenient run nobody asked for is the false green profiles exist to prevent.
    |
    | Overridable here: level, strict_tools, strict_undetermined, use_statistics,
    | assume_server_version, and security.min_severity.
    |
    */

    'profiles' => [

        // A developer's machine: report, do not block. It overrides NOTHING — it is
        // the base config above, under an explicit name. That is deliberate: the
        // shipped base is already lenient (level 0, nothing strict), and an empty
        // `local` means "my normal settings", so a project that raises its base level
        // still gets that level here rather than being forced back down. Naming a
        // value here would make the base config key for it dead whenever `local` is
        // active — which is by default — so the lenient profile stays empty.
        // …with ONE exception, and it is an exception because the premise above stops
        // holding for this key. `security.min_severity` ships at 'high', which is not
        // the lenient end of its scale — unlike `level`, whose base 0 already is. So
        // "empty means my normal settings" would hand a developer the pipeline's floor
        // on every save, and the predictable answer to a local run that blocks on a
        // finding somebody is mid-way through fixing is to stop running it locally.
        // Named here, therefore: report everything, block only on a critical.
        'local' => [
            'security' => ['min_severity' => 'critical'],
        ],

        // A pipeline: strict. A missing tool and a check that could not run both
        // fail the build, because a green that skipped half its checks is worse
        // than a red — it is a red nobody sees. It names ONLY what it tightens over
        // the base; anything it omits keeps the base value.
        'ci' => [
            'level' => 4,
            'strict_tools' => true,
            'strict_undetermined' => true,
            // Named even though it equals the shipped base, and that is the point: a
            // pipeline's floor must not move when a project lowers its own. A project
            // that sets the base to 'none' — a legitimate choice while it works through
            // a backlog — would otherwise get a CI that blocks on nothing, silently.
            'security' => ['min_severity' => 'high'],
        ],

        // The pre-deploy gate carries the MECHANICS here and little more: what it
        // actually enforces belongs to the deploy suite, and presetting that now would
        // be inventing a gate the package cannot yet honor. The severity floor is the
        // exception, for the reason `ci` names it: the strictest moment in a project's
        // day must not inherit a floor somebody lowered for local work.
        'predeploy' => [
            'security' => ['min_severity' => 'high'],
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | External tools
    |--------------------------------------------------------------------------
    |
    | Optional amplifiers. SQLens reaches its own verdicts without any of these;
    | a tool that is present adds findings SQLens cannot reach on its own, and a
    | tool that is absent is reported as a named degradation rather than a
    | silently smaller run. `sqlens:doctor` shows what was found and where.
    |
    | This section states INTENT, not availability. A path can be pinned on a
    | machine where the binary is not installed yet, and the configuration is
    | still valid — what it must never do is describe a tool nobody reads: an
    | unknown tool name or option is a configuration error, never a no-op.
    |
    | path       An absolute path to the binary. null looks on $PATH. A pinned
    |            path that does not run is REPORTED — never quietly replaced by
    |            whatever else is installed, because naming a path is a statement
    |            about which binary produced the verdict.
    | enabled    Whether this tool may contribute findings at all.
    | timeout    Seconds one invocation may take before it is reported as timed
    |            out. Zero would mean "wait forever", which is the harm a bound
    |            exists to prevent.
    | fast_path  Whether the tool may also run behind `sqlens:lint --file=…`.
    |            Off by default: the fast path promises sub-second turnaround so
    |            a pre-commit hook or an editor save stays usable, and a shell-out
    |            to another program is exactly the kind of cost that promise
    |            cannot absorb by accident. Turning it on is a deliberate trade.
    |
    */

    'tools' => [

        'squawk' => [
            'path' => null,
            'enabled' => true,
            'timeout' => 10,
            'fast_path' => false,
        ],

        /*
        | The Postgres Language Server's `dblint`, a schema linter for a LIVE database.
        |
        | It has no `fast_path` key, and the absence is the statement: the single-file route
        | judges one migration file with a sub-second budget, and this tool answers by opening a
        | connection and reading the catalog. There is no version of that route it belongs in, so
        | there is no switch offering to put it there.
        |
        | The timeout is longer than Squawk's for the same reason — measured, a warm local run
        | against a small database took about two and a half seconds, and a bound near that would
        | turn a slightly larger schema into a timeout. A timeout is an `undetermined`: the run
        | would lose the checks over something that is not a problem.
        */
        'pgls' => [
            'path' => null,
            'enabled' => true,
            'timeout' => 30,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | guard — runtime guardrails, on by configuration alone
    |--------------------------------------------------------------------------
    |
    | Every other suite in this package reads. This one WATCHES a running
    | application: it turns on Eloquent's strictness switches, reports a query
    | that took too long, and names DDL executed outside a migration.
    |
    | ⚠️ It is off unless a profile is named, and off means ABSENT rather than
    | cheap: with `profile` null nothing is bound, no listener is registered and
    | no object is built. "Disabled" costing a listener per request is how a
    | safety feature becomes a performance ticket.
    |
    | ⚠️ A profile name this file does not define is an ERROR, not off. A typo
    | that silently disabled every guardrail is exactly what a named profile is
    | supposed to prevent, and a run that treats it as "nothing configured"
    | reports a clean gate over an application nobody is watching.
    |
    | ⚠️ These profiles are a SEPARATE AXIS from the run profiles above. They
    | share the word and nothing else: a run profile decides how strict a lint
    | is, a guard profile decides what a running application refuses to do. One
    | is not an alias of the other, and a project may well want `ci` in one and
    | `production` in the other.
    */
    'guard' => [

        /*
         * The active profile, or null for off. Read once at boot.
         */
        'profile' => null,

        /*
         * The profiles themselves. The three shipped ones are examples in the
         * literal sense: they are meant to be read, adjusted and renamed, not
         * adopted unseen.
         *
         * The names are yours. Everything INSIDE a profile is validated, so a
         * misspelled key is refused rather than quietly ignored — that is the
         * whole reason the guard suite is configuration and not code.
         */
        'profiles' => [

            /*
             * Local development: loud, and it stops you.
             *
             * `throw` is true here and nowhere else. On a developer's machine an
             * exception is the fastest possible feedback and costs nothing but a
             * refresh; the same setting in production takes down a page over a
             * lazy load that would have worked.
             */
            'local' => [
                'strict' => [
                    'lazy_loading' => true,
                    'discarding_attributes' => true,
                    'missing_attributes' => true,
                    'destructive_commands' => false,
                    'throw' => true,
                ],
                'slow_query' => [
                    'enabled' => true,
                    'threshold_ms' => 500,
                    'cumulative_threshold_ms' => 2000,
                ],
                'runtime' => [
                    'runtime_ddl' => true,
                    'unbound_raw_sql' => true,
                ],
                'logging' => [
                    'channel' => null,
                    'level' => 'warning',
                    'include_bindings' => false,
                    'max_sql_length' => 2000,
                ],
                'connections' => [],
            ],

            /*
             * CI: every guardrail on, and it still does not throw.
             *
             * A thrown exception in CI fails the test that met it and hides the
             * rest, so a run that would have found six problems reports one. The
             * log carries all six, and the build reads them together.
             */
            'ci' => [
                'strict' => [
                    'lazy_loading' => true,
                    'discarding_attributes' => true,
                    'missing_attributes' => true,
                    'destructive_commands' => true,
                    'throw' => false,
                ],
                'slow_query' => [
                    'enabled' => true,
                    'threshold_ms' => 1000,
                    'cumulative_threshold_ms' => 5000,
                ],
                'runtime' => [
                    'runtime_ddl' => true,
                    'unbound_raw_sql' => true,
                ],
                'logging' => [
                    'channel' => null,
                    'level' => 'warning',
                    'include_bindings' => false,
                    'max_sql_length' => 4000,
                ],
                'connections' => [],
            ],

            /*
             * Production: watch, report, and never be the reason a page fails.
             *
             * Primum non nocere in a config block. Lazy loading is reported and
             * not refused, because refusing it turns a slow page into a broken
             * one — and the person paged at 3 a.m. would rather have the slow
             * page and the log line.
             *
             * `destructive_commands` is the exception, and it is not a guardrail
             * against SQLens: it is Laravel's own prohibition on `migrate:fresh`
             * and friends, and there is no version of that being wrong here.
             */
            'production' => [
                'strict' => [
                    'lazy_loading' => true,
                    'discarding_attributes' => false,
                    'missing_attributes' => false,
                    'destructive_commands' => true,
                    'throw' => false,
                ],
                'slow_query' => [
                    'enabled' => true,
                    'threshold_ms' => 2000,
                    'cumulative_threshold_ms' => 8000,
                ],
                'runtime' => [
                    'runtime_ddl' => true,
                    'unbound_raw_sql' => true,
                ],
                'logging' => [
                    'channel' => null,
                    'level' => 'warning',
                    // False, and it is the one default here nobody should change
                    // without saying why: bindings are ROW DATA, and a log is the
                    // one place row data reaches somewhere with different access
                    // rules than the database it came from.
                    'include_bindings' => false,
                    'max_sql_length' => 1000,
                ],
                'connections' => [],
            ],

        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | format — one house style for the SQL your migrations contain
    |--------------------------------------------------------------------------
    |
    | `sqlens:format` rewrites the raw SQL in your migrations to one style, and
    | `--check` answers whether it would have to, which is the form a CI step
    | uses.
    |
    | ⚠️ `backend` is the one key worth understanding before setting it. `auto`
    | picks the best AVAILABLE backend — pgFormatter, then SQLFluff, then the
    | built-in PHP core, which is always there. NAMING one is a promise that it
    | is installed: a named backend that cannot run is a REFUSAL rather than a
    | quiet fallback, because a fallback would produce output you did not ask
    | for, and the next machine — the one where the binary IS installed — would
    | rewrite every file.
    */
    'format' => [

        /*
         * WHERE to look for SQL files. Empty means the application's registered
         * migration paths, which is right for most projects and wrong for the one
         * that keeps its SQL somewhere else — `database/sql/`, `db/`, a legacy
         * dump directory. Name those roots here rather than on every invocation.
         *
         * Repo-relative. `format` is the only suite that WRITES, so this list is
         * the blast radius rather than a convenience.
         */
        'paths' => [],

        /*
         * Globs excluded from every run, matched against the walked path; a
         * repo-relative glob is anchored for you, so `database/schema/*` works.
         *
         * The default protects `schema:dump`'s output. That file is written from
         * the database in whatever shape the dumper produces, so reformatting it
         * makes the next dump a large diff against a file nobody edits — visible
         * on every deploy. A project that hand-maintains its schema file can take
         * the entry out; the run then NAMES the dump files it touched, so the
         * decision shows up in the output and not only here.
         *
         * `vendor/`, `node_modules/` and `storage/` are never walked into and are
         * deliberately not on this list: they are not a preference.
         */
        'exclude' => ['database/schema/*'],

        /*
         * Which extensions count as a SQL file. Without the dot.
         *
         * ⚠️ `php` and `phtml` are RESERVED and cannot be added. A Laravel
         * migration is a PHP file whose SQL, where there is any, lives inside a
         * heredoc — running a SQL formatter over one does not format that SQL, it
         * reads the whole file as a statement and rewrites it. That is a destroyed
         * migration, reported as `reformatted`. The refusal is not a warning
         * because the outcome is data loss rather than a bad report.
         *
         * So this key widens the set to other files that hold nothing but SQL
         * (`.ddl`, `.psql`, `.pgsql`), never to files that hold a program.
         */
        'extensions' => ['sql'],

        /*
         * `auto`, `php`, `pgformatter` or `sqlfluff`.
         */
        'backend' => 'auto',

        /*
         * `auto`, `pgsql` or `mysql`. With `auto` the dialect follows the
         * connection this package is pointed at — which is right nearly always
         * and wrong in the one case worth naming: a repository whose migrations
         * target a different engine than the connection it happens to be
         * configured with. Name it there.
         */
        'dialect' => 'auto',

        /*
         * Where the external backends live, when they are not on PATH.
         *
         * Three answers, and the third is the one the other two cannot give:
         *
         *   null        look on the search path
         *   '/a/path'   it is here
         *   false       this project does without this backend
         *
         * A path that is set and wrong is an error with a name, never a silent
         * fallback to another backend.
         *
         * The difference between the first and the last is what a run REPORTS.
         * A backend that is merely missing is a loss: the machine that has it
         * formats differently, the output is committed, and the next run there
         * rewrites every file -- so it is named, and `--strict-tools` refuses.
         * One you switched off is a decision, and telling you on every run that
         * you are missing what you chose to do without is how a report stops
         * being read.
         */
        'binaries' => [
            'pgformatter' => null,
            'sqlfluff' => null,
        ],

        /*
         * A bound, not a suggestion. A formatter without one holds a CI step —
         * and the whole shared queue behind it — for as long as it stands.
         */
        'timeout' => 15,

        /*
         * The house style. Four options, and the fewness is deliberate: every
         * option is a decision two people will disagree about forever, and a
         * formatter's value comes from ending that argument rather than
         * parameterizing it.
         *
         * A backend that cannot express one of these REPORTS that rather than
         * ignoring it — otherwise you would get output you did not ask for and
         * no signal that it had happened.
         */
        'style' => [
            'indent' => 4,
            'uppercase_keywords' => true,
            // The one purely aesthetic option here, and it is present because it
            // is the one people argue about: leading commas make a git diff of an
            // added column one line instead of two.
            'leading_commas' => false,
            // ⚠️ THE ONLY OPTION THE BUNDLED BACKEND CANNOT HONOR. The pure-PHP
            // core wraps on STRUCTURE — per column, per clause, per bracket depth
            // — and never on a column count, so it cannot bound a line at 100 or
            // at anything else.
            //
            // It does not ignore the value: asked for a width other than this
            // default, it reports `format_style_not_expressible` and names the
            // option, exactly as the pgFormatter backend does for the same key.
            // Left at the default, nothing is refused and nothing is claimed.
            //
            // So a column bound needs the `pgformatter` or `sqlfluff` backend.
            // Whether the core should grow one is an open question and not an
            // oversight -- it belongs to the layout code that idempotence and
            // determinism both hang on, and any wrapping algorithm there has to
            // prove a second pass changes nothing. See the format documentation
            // page, which carries the same explanation for a reader who never
            // opens this file.
            'line_width' => 100,
        ],

    ],

];
