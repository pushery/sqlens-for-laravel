<?php

declare(strict_types=1);

// The human-facing labels of the console balance. Everything a MACHINE reads —
// rule ids, message prefixes, finding text, JSON keys, exit-code descriptions —
// is public API and stays English (US) in every locale, because translating a
// contract would break both determinism and every consumer parsing it.
//
// Register: informal (per-Du) in every locale. Genuine loanwords the field uses
// untranslated (level, severity, security) are left standing.

return [
    'drivers' => [
        'reserved_driver' => 'SQLens does not support :driver. Its rules are written for PostgreSQL 18+ and MySQL 8.4+, and applying MySQL rules to another engine would produce confident, wrong advice. Nothing was checked on this connection. These engines are declared non-goals rather than gaps: DriverRegistry::extend() refuses their names outright, so the answer is settled.',
        'unknown_driver' => 'SQLens does not know the driver :driver. It is neither built in nor registered through DriverRegistry::extend(), so nothing was checked on this connection — an unknown engine is a finding, never a free pass. If :driver should be supported, a contribution or an issue is genuinely welcome.',
        'missing_driver_key' => 'The connection :connection declares no driver, so SQLens cannot tell which engine it addresses and checked nothing on it. Add a driver key to the connection.',
        'connection_not_found' => 'No connection named :connection is configured, so SQLens had nothing to check. The application configures: :configured. Fix the name in sqlens.connection, or add the connection.',
        'version_below_floor' => 'The :driver server reports version :detected, below the :required SQLens supports. Its rules describe behavior that older versions do not have, so nothing was checked on this connection. Upgrade the server, or pin an assumed version if you know what you are doing.',
        'unknown_server_version' => 'SQLens could not establish the version of the :driver server on :connection, so nothing was checked. A version it cannot read is a finding, not a pass.',
        'mariadb_behind_mysql_driver' => 'The :connection connection uses the Laravel mysql driver, but the server answering is a MariaDB (:detected). SQLens rules are written against MySQL 8.4 and describe behavior MariaDB does not share, so applying them here would produce confident, wrong advice. Nothing was checked. MariaDB is a declared non-goal rather than a gap: the supported engines are PostgreSQL and MySQL.',
        'unverified_engine_identity' => 'No connection was open, so SQLens could not confirm that the :driver driver on :connection really addresses that engine — the configured driver name alone is not proof. Nothing was checked, and this gap is reported rather than assumed away.',
    ],
    'reporting' => [
        'summary' => 'summary',
        'fail' => 'fail',
        'undetermined' => 'undetermined',
        'not_applicable' => 'not applicable',
        'suppressed' => 'suppressed',
        // The denominator, so a count is readable as a proportion rather than as an absolute. It
        // reads "over 32 migrations" beside the counts, and the singular case says "1 migration".
        'over_subjects' => 'over :count :noun',
        'subject_singular' => 'migration',
        'subject_plural' => 'migrations',
        'level_findings' => 'Level findings',
        'security_findings' => 'Security findings',
        'level_gate' => 'Level gate',
        'severity_gate' => 'Security severity gate',
        'breaching' => 'breaching',
        'gate_off' => 'off',
        'by_level' => 'by level',
        'by_severity' => 'by severity',
        'by_downtime' => 'by downtime class',
        'by_suppressed_axis' => 'suppressed by axis',
        'by_suppression_source' => 'by suppression source',
        'stale' => 'stale',
        'suppressed_heading' => 'suppressed:',
        'reason' => 'reason',
        'until' => 'until',
        'undetermined_allowed' => 'undetermined allowed by config',
    ],
    'shadow' => [
        'confirm' => 'Shadow mode will CREATE and DROP a throwaway database on the :connection connection. It never touches your data, but it does create and drop a database of its own. Proceed?',
        'aborted' => 'Shadow mode aborted — no throwaway database was created.',
        'configure_direct_connection' => 'Configure a direct connection under capture.shadow.direct_connection: template operations cannot run behind a transaction pooler.',
        'run_schema_dump' => 'Run `php artisan schema:dump` so shadow mode has a schema dump to rebuild the throwaway MySQL database from.',
        'unsupported_engine' => 'Shadow mode does not support :engine — it runs only against PostgreSQL and MySQL.',
        'kept_on_failure' => 'The throwaway database :database was kept for debugging (keep_on_failure is on). Drop it by hand when you are done.',
        'orphan_found' => 'Found :count leftover shadow database(s) from an earlier run.',
        'orphan_swept' => 'Removed :count leftover shadow database(s) left behind by an earlier run.',
        'reason' => [
            'guard_blocked' => 'The production guard blocked shadow mode, so nothing was run.',
            'transaction_pooling' => 'The target sits behind a transaction pooler; configure a direct connection so template operations can run.',
            'replica' => 'The target is a read replica; shadow mode runs only against the write instance.',
            'insufficient_privileges' => 'The role cannot create a database, so the throwaway database could not be provisioned.',
            'schema_dump_missing' => 'The MySQL schema dump is missing or unreadable; run php artisan schema:dump.',
            'dump_unparseable' => 'The MySQL schema dump could not be read safely, so no part of it was replayed.',
            'migrate_failed' => 'An earlier migration failed the real migrate, so this one was not run.',
            'teardown_failed' => 'The throwaway database could not be dropped and may need to be removed by hand.',
            'session_timeout' => 'The shadow session hit its own statement, lock, or idle-transaction timeout.',
        ],
    ],
    'commands' => [
        'file_not_found' => 'The --file ":file" does not exist or cannot be read.',
        'file_not_php' => 'The --file ":file" is not a PHP migration file.',
        'file_outside_paths' => 'The --file ":file" is outside the configured migration paths; --file lints a migration, not an arbitrary file.',
        'file_multiple' => '--file accepts exactly one migration file.',
        'file_shadow_conflict' => '--file cannot be combined with --shadow; the fast path is pretend-only.',
        'roundtrip_requires_shadow' => '--roundtrip only runs in shadow mode: it replays down() for real, which is destructive by design, so it needs a throwaway database. Add --shadow.',
        'roundtrip_connection_conflict' => '--roundtrip cannot be pointed at a named connection with --connection: it runs only against the throwaway database it creates itself.',
        'roundtrip_file_conflict' => '--roundtrip cannot be combined with --file: the fast path lints one migration without a database, and a roundtrip needs one it may break.',
        'defaulted_config' => 'The sqlens configuration does not set :count key(s); the shipped default applies to each. Harmless — but if your published config was meant to set them, re-add them:',
        'invalid_config' => 'The sqlens configuration has :count problem(s). Nothing ran — a key this package does not understand is a key it ignores, silently:',
        'invalid_level' => 'Invalid --level ":level": the level must be an integer from 0 to 9.',
        'invalid_min_severity' => 'Invalid --min-severity ":severity": expected one of :available, or \'none\' to report without blocking.',
        'invalid_debt_mode' => 'Invalid --debt ":mode": expected one of :available. Nothing ran — a mode this build does not know is one it would silently treat as \'check\', and you would believe you had asked it to record.',
        'unknown_category' => 'Unknown category ":category". Available categories: :available.',
        'unknown_format' => 'Unknown report format ":format". Available formats: :available.',
        'unknown_profile' => 'Unknown profile ":profile". Available profiles: :available.',
        'output_unwritable' => 'Could not open the --output file ":file" for writing.',
        'baseline_no_path' => 'No baseline path is configured. Set sqlens.baseline.path or pass --path=<file>.',
        'baseline_dry_run' => 'Dry run: would write :count finding(s) to :path.',
        'baseline_written' => 'Wrote :count finding(s) to :path.',
        'baseline_unwritable' => 'Could not write the baseline file ":path".',
        'agent_rules_unknown_target' => 'Unknown --target ":target". Use one of: :known.',
        'agent_rules_output_needs_one_target' => '--output writes one path, so it needs a single --target. One file cannot hold three artifacts.',
        'agent_rules_written' => 'Wrote :path.',
        'agent_rules_check_missing' => ':path is missing. Run sqlens:agent-rules to create it.',
        'agent_rules_check_stale' => ':path is out of date. Run sqlens:agent-rules to update it.',
        'agent_rules_check_current' => 'Every agent context file is current (:count checked).',
        'agent_rules_unknown_ignore_rule' => 'A suppression names a rule that does not exist, so no catalog can be resolved: :violations',
    ],
    'catalog' => [
        'estimate' => [
            'estimated' => 'estimated',
            'exact' => 'exact at read time',
            'never_collected' => 'statistics never collected',
            'age_unknown' => 'statistics age unknown',
            'measured_at' => 'statistics from :timestamp',
        ],
        'skip' => [
            'not_readable' => 'The catalog relation :reference could not be read on this server, so the objects it describes are missing from this reading. Not a permission problem — that is reported separately — and not a pass: what was not read is listed rather than assumed empty.',
            'insufficient_privilege' => 'The connecting role lacks the privilege to read :reference, so its objects are missing from this reading. This is the ordinary case on a managed database, where a non-superuser sees a fraction of the catalog. Grant the reader role SELECT on it, or accept a partial audit that says which part it is.',
            'not_understood' => 'SQLens read :reference but did not understand it well enough to reason about — an expression index, a partial index whose predicate it did not compare, a view definition. It is reported rather than guessed at: a wrong answer about an index costs more than a missing one.',
            'excluded_by_config' => '\':reference\' was left out deliberately — by configuration, or by a documented default such as excluding objects an extension owns. A decision, not a gap.',
            'prefix_matched_nothing' => "A table prefix is configured, but nothing in the audited schemas carries ':reference'. Reported rather than returned as an empty reading: the likeliest cause is a prefix that is simply wrong — copied from another project, or read from a connection this application does not use — and an audit of nothing must never read like an audit of a clean schema.",
            'unsupported_driver' => 'The :driver reader has no support for :reference, so nothing was attempted. A gap in this package, not in your database.',
            'budget_exceeded' => 'The catalog read stopped at :reference because it reached its own time or query budget. SQLens bounds itself so an audit never becomes the problem it is auditing — and a bounded read that stopped early says so rather than reporting the part it managed as the whole.',
            'unmapped_lock_mode' => 'The server reported a lock on :reference in a mode this build has no neutral name for, so it could not be classified. The wait is still in the report: an unfamiliar mode is one nobody here has reasoned about, which makes it more worth seeing than any mode that maps.',
            'instrumentation_disabled' => 'The server can answer about :reference, but its instrumentation is switched off, so it has nothing to report. This is not an empty result: an idle server and a blind one look identical here, so nothing was concluded from the silence. On MySQL, turning `performance_schema` on requires a server restart.',
            'unexpected_error' => 'Reading :reference failed with an error SQLens did not anticipate (:code). It is reported under its own reason and with its code, so a real fault is not filed away as a server that simply does not have the object.',
        ],
    ],
    // The notes that travel with a remediation payload. The STRUCTURE of a fix is what a
    // machine acts on and stays English in every locale; these are the sentences for the
    // person reading over the agent's shoulder, so they are translated.
    'remediation' => [
        'invalid' => [
            'no_steps' => 'SQLens built a fix template for this finding and then refused it: it carried no steps at all. That is a defect in SQLens, not in your migration — the finding above stands. Please report it with the rule id.',
            'step_order' => 'SQLens built a fix template for this finding and then refused it: its steps were not numbered 1, 2, 3 without a gap, and a gap reads as a step that was written and lost. That is a defect in SQLens, not in your migration — the finding above stands. Please report it with the rule id.',
            'none_carries_a_sequence' => 'SQLens built a fix template for this finding and then refused it: it declared that no safe standard sequence exists and then carried one. Both halves look correct alone, which is exactly why it must not ship. That is a defect in SQLens, not in your migration — the finding above stands. Please report it with the rule id.',
            'note_key' => 'SQLens built a fix template for this finding and then refused it: one of its notes was not a translation key, so it would have reached you as a raw key instead of a sentence. That is a defect in SQLens, not in your migration — the finding above stands. Please report it with the rule id.',
            'downtime_class_without_a_deploy' => 'SQLens built a fix template for this finding and then refused it: it named a downtime class for a finding about a state your database is already in. There is no deploy here whose effect that could describe — what it costs arrives when somebody writes the migration, and depends on what they write. A reader would have taken it as a statement about their next deploy. That is a defect in SQLens, not in your database — the finding above stands. Please report it with the rule id.',
            'this_migration_without_a_migration' => 'SQLens built a fix template for this finding and then refused it: one of its steps said "in this migration" for a finding that came from reading your database rather than a migration. There is no migration at hand to put it in; the fix is a new one. That is a defect in SQLens, not in your database — the finding above stands. Please report it with the rule id.',
            'placeholder' => 'SQLens built a fix template for this finding and then refused it: one of its statements carried a broken placeholder — an unclosed brace, an empty name — which means a substitution went wrong. A statement that reads like SQL and is not is the one thing a fix template must never hand you. That is a defect in SQLens, not in your migration — the finding above stands. Please report it with the rule id.',
        ],
        'atomicity_split' => [
            'schema_first' => 'Put the schema change in a migration of its own and let it finish. On MySQL it commits the moment it runs — that is not something you can switch off, and it is why the two halves cannot share a fate. Alone in its own file, this half either completes or leaves nothing behind.',
            'mind_the_gap' => 'Decide what the gap between the two migrations means for the running application. Between them the schema is live and the data is not: a new column exists and is empty, a new constraint is in force with nothing backfilled behind it. Whether that is harmless for a few minutes or is itself the incident is a question about your application, and it is the question the split forces you to answer instead of discovering.',
            'data_second' => 'Put the data write in the NEXT migration, or in a queued job. If it fails there, the schema change already shipped and stays shipped — you re-run one step rather than reasoning about a half-applied file. A backfill large enough to need bounding belongs in a job; the batching recipe is MY.L7.UNBATCHED_MASS_DML\'s.',
            'precondition' => [
                'ddl_commits_implicitly' => 'This rests on one fact about MySQL, and it has no setting: EVERY DDL statement causes an implicit commit. There is no transaction wrapping a MySQL migration — Laravel\'s grammar reports supportsSchemaTransactions() as false — so a mixed migration is never atomic, whatever it looks like in the file.',
                'down_must_match_the_halves' => 'Split down() the same way you split up(). Two migrations mean two rollbacks, each undoing its own half — and the one that undoes the schema change has to cope with the data migration having run OR not, because after the split those are two separate deploys.',
            ],
            'verification' => 'Run sqlens:lint again. This rule reads the migration\'s statement stream, so it answers without a database: it goes quiet as soon as no data write follows a schema change in the same file. It cannot check that you split down() as well — that half is on you, and the roundtrip checks (CAP.L0.DOWN_FAILED, CAP.L0.DOWN_NOT_INVERTIBLE) are what catch it if a run captures one.',
        ],
        // The drift corrections. Structured material a person or an agent applies and SQLens then
        // re-verifies — never a change this package makes. The unexpected-in-database case names
        // BOTH routes on purpose: which one is right depends on why the object is there, and that
        // is the one thing the comparison cannot see.
        'drift' => [
            'verification' => 'Run sqlens:drift again. It re-reads the live catalog and replays the migration state, so the difference disappears from the report the moment the two really agree — not when a file looks right. If the difference was deliberate after all, it belongs in the exclude file with a reason instead.',
            'unexpected' => [
                'decide_first' => 'Decide why this object is in the database and in no migration, before writing anything. The two honest answers lead in opposite directions, and SQLens deliberately does not choose between them: a hotfix that was applied and never committed should be adopted, and something created by hand for a one-off should be removed. Only you can tell which happened.',
                'adopt_it' => 'If it was meant to be there: write the migration that creates it. Until you do, every rebuilt environment — a fresh clone, a CI run, the next migrate:fresh — is missing it, and the difference will be reported again on every drift run.',
                'retire_it' => 'If it was not meant to be there: remove it in a destructive migration of its own, and run sqlens:lint over that migration first. Dropping an object is the one correction that cannot be undone by re-running anything, so it belongs in a window you chose rather than at the end of an ordinary deploy.',
                'precondition' => [
                    'know_why_it_is_there' => 'This rests on something SQLens cannot read: the object\'s history. The comparison sees that no migration describes it; it cannot see whether that is an accident or a decision, and it has no way to find out. Check the deploy log, the incident channel, or whoever was on call.',
                ],
            ],
            'missing' => [
                'read_the_migration_table' => 'Read the migrations table first. A migration that never ran and one that ran without doing what it claims leave exactly the same absence in the schema, and they need opposite fixes — this query is what tells them apart.',
                'never_edit_an_applied_migration' => 'If the migration IS recorded as run, fix it with a NEW migration rather than by editing the old one. The old one is recorded as applied on every other environment; editing it makes those environments silently disagree with the file that describes them, and nothing will report that disagreement until somebody rebuilds one.',
                'precondition' => [
                    'two_causes_one_absence' => 'One absence, two causes, and this comparison cannot separate them: it compares two states, and there is no history in it. The migrations table is where the answer lives.',
                ],
            ],
            'divergent' => [
                'decide_which_side_is_right' => 'Decide which side is right before writing the ALTER. The database may be correct and the migration stale, or the reverse — the comparison reports that they differ, not which one is the mistake.',
                'alter_one_attribute_at_a_time' => 'Change one attribute per statement. A single ALTER that moves a type and a collation together is one statement you cannot roll back halfway, and on a large table it is also one lock held for the sum of both rewrites rather than for each in turn.',
                'lint_the_correction' => 'Run sqlens:lint over the correction migration before deploying it. The correction is itself a migration, and putting a type back can rebuild the whole table under a lock — which is the outage this package exists to prevent, arriving through the fix rather than through the original change.',
                'precondition' => [
                    'the_alter_is_itself_a_migration' => 'This correction carries the rewrite downtime class, and that is not the finding\'s class. Reporting a difference changes nothing and takes no lock; ALTERing a column to remove it can rewrite every row. Plan it as you would plan any rewrite — the finding was free, the fix is not.',
                ],
            ],
        ],
        'no_safe_sequence' => [
            'truncate_mysql' => 'There is no standard sequence for this, and on MySQL there is no transaction protecting you either — TRUNCATE is DDL, so it causes an implicit commit and the rows are gone the instant the statement runs, whatever fails afterwards in the same migration. down() is the only path back and it cannot restore data. Every real remedy is a decision about your data: reference data being reloaded wants an idempotent seeder, a table being retired wants the staged drop, a test fixture in the wrong file wants deleting. Decide, then say so on the migration with #[SqlensAllowDestructive] and a reason — that records the review; it does not silence the finding.',
            'no_primary_key_on_create' => 'There is no standard sequence for this, because WHICH key is a schema decision — but the timing is not, and that is the part worth acting on now. This table is empty, so adding a primary key costs nothing at this moment; the same key added to a populated table later is a COPY ALTER that rebuilds every row under a shared lock. A surrogate id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY is usually the right answer and is what Laravel\'s $table->id() gives you. SQLens does not write it for you: on InnoDB the primary key IS the physical row order, so choosing it is choosing how the table is stored.',
            'no_primary_key_after_drop' => 'There is no standard sequence for this, because putting a key back needs a candidate that is unique AND NOT NULL across every row already in the table — a fact about your data, which SQLens never reads. If a natural candidate exists, add it as the primary key in a migration of its own and expect a table rebuild. If none does, the route is the staged swap: add a surrogate column, backfill it in batches, then promote it — never a one-line ALTER on a table this size. And check the migration first: if the drop was only meant to precede a new key, the new key belongs in the same migration.',
            'fk_target_non_unique' => 'There is no standard sequence for this, and there is no plan being withheld either — MySQL 8.4 REJECTS this statement outright (ERROR 6125), so no staging makes it work. The deploy fails at this line whatever happens around it. Every route out changes what the REFERENCED table promises: add a unique key over exactly the referenced columns, point the foreign key at a key that already exists, or drop the constraint. Two of those change that table\'s write behavior for every other consumer of it, which is why SQLens does not pick one from a single statement\'s worth of context.',
            'schema_decision_verification' => 'Run sqlens:lint again once you have decided. The rule reads the migration, so it answers without a database and without running anything — it goes quiet as soon as the statement says what it needed to say. It will not tell you the decision was a good one; it only tells you the statement is no longer missing the thing it was missing.',
            'clause_is_ignored' => 'There is no clause worth naming here, because this operation ACCEPTS the clause and ignores it. EXCHANGE PARTITION takes even ALGORITHM=COPY, LOCK=NONE — a self-contradictory pair every other statement rejects — and runs the same way regardless. Pinning it would hand you a guarantee the server never makes, which is worse than pinning nothing: you would read the clause later and believe the operation was checked. Plan this one on what it actually costs instead, which the finding\'s downtime class states.',
            'algorithm_lock_verification' => 'Run sqlens:lint again once you have pinned the server version or written the clause. The rule goes quiet as soon as the statement carries ALGORITHM= and LOCK=, because at that point the server, not SQLens, is the one enforcing it. If MySQL then REFUSES the statement, that is the clause working: the answer is to stage the change, not to remove the clause.',
            'dml_without_where' => 'There is no standard sequence for this, because the fix is the predicate you meant — and it is in your head, not in the statement. SQLens could only offer you WHERE {{predicate}}, which is this finding restated as a form to fill in, and anything more specific would be a GUESS. A guessed predicate on a DELETE removes the wrong rows, which is the exact harm this rule exists to prevent. Two ways finish this: write the WHERE you meant, or — if the whole-table write really is intended — declare it on the migration with #[SqlensAllowDestructive] and a reason.',
            'down_missing' => 'There is no standard sequence for this, and a generated one would be dangerous rather than merely unhelpful. Inverting the statements looks mechanical — ADD COLUMN becomes DROP COLUMN — and that is precisely how a generated down() destroys data: the inverse of "add a column and backfill it" is not "drop the column", it is "drop the column and lose everything written into it since". A rollback runs when a deploy is already going wrong, which is the worst possible moment to find out the way back was written by a tool that could not see your data. Two answers finish this, and one of them is short: write the down() that undoes THIS up(), or — where the change genuinely cannot be undone — throw from down() with that reason, so the answer is recorded rather than absent.',
            'down_more_destructive' => 'There is no standard sequence for this, and the obvious one would be the wrong thing to hand you. SQLens has a staged-drop sequence, and pointing at it here would be advice to CARRY OUT the destruction — correct only if you meant it, and the likelier reading is a dropIfExists copied in from the migration next door. A payload cannot tell those apart, and only one of the two mistakes is recoverable. So: if the rollback is asymmetric by accident, narrow it to the inverse of up() and nothing else. If the removal was genuinely intended, it does not belong in a down() at all — put it in an up() of its own, where the deploy-window sequence applies and where somebody decides to run it.',
            'down_verification' => 'Run sqlens:lint again — this rule reads the migration file, so it answers without a database and without running your rollback. It goes quiet once down() is written, or once it throws with a named reason. If the run captures a roundtrip, the two runtime checks take it from there: whether down() raised (CAP.L0.DOWN_FAILED) and whether it actually undid the schema (CAP.L0.DOWN_NOT_INVERTIBLE).',
            'drop_schema' => 'There is no standard sequence for this, because the sequence a schema drop needs is decided by what is IN the schema — and this rule reads one statement, not a catalog. Retiring a namespace is retiring each thing inside it: tables that still hold data want the staged drop, tables that moved want ALTER TABLE ... SET SCHEMA, and a view somebody else depends on wants a conversation before either. SQLens will not order that list for you from a single DROP. What it can say is how to make the last step safe: once the schema really is empty, DROP SCHEMA ... RESTRICT succeeds, and RESTRICT is PostgreSQL\'s default precisely so that the statement refuses when the retirement is not finished. CASCADE waives that check, which is why it is the form worth a finding.',
            'truncate' => 'There is no standard sequence for this, and that is the honest answer rather than a gap. Every real remedy is a decision about your data: reference data being reloaded wants an idempotent seeder, a table being retired wants the staged drop, and a test fixture in the wrong file wants deleting. Those lead to different actions and SQLens cannot see which one this is. Decide, then say so on the migration with #[SqlensAllowDestructive] and a reason — that records the review; it does not silence the finding.',
            'verification' => 'Run sqlens:lint again. The rule still reports this statement — it is supposed to — but with the opt-in it reports as a named suppression carrying your reason instead of as an unexamined destructive change. That is the difference this step is for.',
        ],
        'transaction_split' => [
            'one_migration_per_table' => 'Give each table its own migration. PostgreSQL holds every lock a transaction takes until it COMMITS, so a migration that alters three tables does not lock each for its own duration — it locks the first for the duration of all three. Traffic to whichever table you touched first queues behind the slowest operation in the file.',
            'do_not_over_split' => 'Do not split further than that. Several ALTER clauses on the SAME table in one statement are ONE lock, not a bundle — separating those takes the same lock several times and makes the total longer. The thing to separate is tables, not clauses.',
            'order_still_matters' => 'Check the order before you renumber. Migrations that were one transaction may have depended on each other, and once they are separate files a failure in the middle leaves the earlier ones applied. That is usually what you want; it is never something to find out afterwards.',
            'verification' => 'Run sqlens:lint again — the rule counts strong locks per transaction, so it goes quiet when each migration holds one. What the split costs in wall-clock is not something SQLens can see: it reads migrations, not your deploy.',
            'precondition' => [
                'no_all_or_nothing_requirement' => 'The changes do not have to succeed or fail together. That is the one thing the single transaction was buying, and splitting it is the moment you give it up — deliberately, or not at all.',
            ],
        ],
        'charset_migration' => [
            'check_index_lengths' => 'Before anything else, check what your index keys become. utf8mb3 reserves three bytes per character and utf8mb4 reserves four, and InnoDB counts its key limit in BYTES — so a key that fitted at 765 bytes becomes 1020, and a composite that fitted at 3000 becomes 4000 and is refused outright. This is how the migration usually ends: not slowly, but immediately, with an error, on a table that may already be half converted. What to do about a key that no longer fits — shorten the prefix, narrow the column, drop the index — depends on what that index is FOR, so SQLens offers no number here.',
            'convert' => 'Then convert. This re-encodes every value in every string column, so the table is copied row by row under a shared lock and writes queue for the whole run. Pin ALGORITHM and LOCK with the values the online-DDL matrix records for this operation, following that recipe — it does not make the copy cheap, it makes the server tell you before it starts.',
            'follow_the_connection' => 'Now bring the connection and the server side across. A converted column with a connection still speaking utf8mb3 accepts the writes and stores the replacement character — silently. The table is utf8mb4, the data is not, and nothing errors. This is the step whose absence is discovered months later by a user with an emoji in their name.',
            'window_or_stage_it' => 'On a table of any size, plan the window or stage it — convert the table on a replica and promote it, or move the data into a new table in batches. The size that decides which is worth doing is not in the statement.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. What the columns actually became is a question for the catalog: sqlens:audit reports a column still on utf8mb3, and that is the answer this statement was aiming at.',
            'precondition' => [
                'collation_is_a_decision' => 'You have chosen the collation deliberately. utf8mb4 has several and they sort and compare differently — accent sensitivity, case sensitivity, Unicode version. Converting is the moment that choice is made, and re-running the statement later does not undo it.',
                'size_is_an_estimate' => 'Any row count or table size you have seen from SQLens is an ESTIMATE read from catalog statistics. It is good enough to tell a small table from a large one and never good enough to plan a window around.',
            ],
        ],
        'algorithm_lock' => [
            'pin_the_clause' => 'Issue it as a raw statement naming both clauses, and leave a comment saying why. Laravel\'s MySQL grammar cannot emit ALGORITHM= or LOCK=, so raw SQL is a deliberate exception here rather than the normal way to write a migration — and the next reader has to be able to tell those apart. The two values come from the online-DDL matrix entry for this operation; they are not a preference.',
            'expect_a_refusal' => 'Be clear about what you just bought. The clause does NOT make a copying operation online — it makes the server REFUSE. An operation MySQL can only do by copying now fails with an error instead of quietly copying the table, so the deploy stops before it locks anything rather than in the middle of it. If it does fail, that is the clause working, and the answer is to stage the change, not to remove the clause.',
            'plan_a_window' => 'This operation rewrites the table, and pinning the clause does not change that. Plan the window, or stage the change so the rewrite happens on a table nobody is reading.',
            'no_window_needed' => 'This operation does not rewrite the table, so there is nothing to schedule around it. The clause is here to keep it that way on a server that might have chosen otherwise.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this statement. What the server actually does with the clause is visible at deploy time: it either runs or it refuses, and both answers are more than the builder gave you.',
            'precondition' => [
                'raw_sql_is_an_exception' => 'You are comfortable with a raw statement here. It is the only way to express these clauses, and it costs the schema builder\'s portability — which is a fair trade for this statement and a bad habit for every other one.',
                'version_matches_the_entry' => 'The server you deploy to matches the version this entry was measured against. The matrix records what an operation does per version, and a value read for one and run on another is the guess this whole arrangement avoids.',
            ],
        ],
        'enum_append' => [
            'add_value' => 'Add the value in a migration of its own. On PostgreSQL 12 and later this may run inside a transaction — the old blanket rule that it cannot is no longer true, and repeating it would cost you a deploy step for nothing. What is still true is the next line.',
            'use_it_afterwards' => 'Do not USE the new value in the same transaction that added it. That restriction is real on PostgreSQL 18 and it is what the separate migration is for: add it in one deploy, write it from the next.',
            'irreversible' => 'Know that this cannot be undone. There is no ALTER TYPE … DROP VALUE, so a down() cannot remove what this adds and the migration will not roll back cleanly. If the value set changes often, a lookup table is the shape that does roll back.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. That the value is unused until the next deploy is not something SQLens can check: it reads migrations, not application code.',
            'precondition' => [
                'append_is_all_you_need' => 'Appending really is enough. If a value also has to go away or be renamed, this is not your sequence — PostgreSQL has no statement for either, and the remedy is a new type with the column staged onto it.',
                'readers_tolerate_unknown_values' => 'Everything reading the column copes with a value it does not know yet. Between the two deploys the type has a member the old code has never seen, and a strict match somewhere downstream is where that surfaces.',
            ],
        ],
        'mysql_enum' => [
            'compare_with_the_live_column' => 'Start by comparing the new member list with the one on the live column. MySQL\'s MODIFY names the whole definition, not the change, so six different operations produce statements that look alike — appending, appending past the 255-member boundary, inserting, removing, reordering, renaming. Until you have compared, you do not know which one you are about to run.',
            'append_at_the_end' => 'If it is an append AT THE END, run it. That is the one case that is both instant and safe: nothing is rewritten and no stored value changes meaning.',
            'anything_else_is_staged' => 'Anything else needs staging, and one of them needs it most. Inserting, removing and reordering rewrite the table. RENAMING is the trap: the stored values are ordinals, so a rename takes no lock at all — and every row that read the old name now reads the new one, in an application nobody redeployed. Add the new member, ship the code that accepts it, migrate the rows, remove the old member in a later release.',
            'verification' => 'Run sqlens:lint again — the rule reports this shape whatever kind of change it is, so a green run here means the statement is gone, not that the change was safe. That judgment came from your comparison in step one.',
            'precondition' => [
                'you_know_which_change_this_is' => 'You have actually made the comparison. This is the one precondition the whole sequence rests on: SQLens reports the shape and cannot tell the six apart, so an unchecked assumption here is the failure this sequence exists to prevent.',
                'rename_is_not_free' => 'You are not treating the cheapest option as the safest. A rename is the only member change MySQL performs instantly and the only one that silently reinterprets data already written.',
            ],
        ],
        'rewrite_avoidance' => [
            'add_column' => 'Add a second column in the target type, nullable and without a default — on a current PostgreSQL that is a metadata change, not a rewrite. Nothing reads it yet.',
            'backfill' => 'Copy the values across from a queued job, in bounded batches. Follow the batching recipe rather than writing a loop here: a migration that holds a transaction open for the copy is the outage you are avoiding.',
            'dual_write' => 'Ship a release that writes BOTH columns and reads the new one, and leave it running for at least one full release. Until every running instance has stopped using the old column, swapping them breaks whatever is still there.',
            'carry_over_indexes' => 'Give the new column whatever the old one had — index, unique constraint, foreign key — and build it CONCURRENTLY, following that recipe. Skipping this trades a rewrite for a blocking index build and nobody is better off; doing it after the swap means the new column spends the interval unindexed.',
            'drop_old_column' => 'Drop the old column, in a LATER release. Metadata only.',
            'rename_into_place' => 'Then rename the new one into its place. PostgreSQL will not accept this in the same ALTER TABLE as the drop, so it is a second statement — in the same migration, right after it. Metadata only as well.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. What SQLens cannot check is the interval between the phases: it reads your migrations, not which release is running.',
            'precondition' => [
                'values_fit_the_new_type' => 'Every existing value fits the new type. The backfill is where a value that does not will surface, one batch in, rather than at the start — so look at the data before the first phase and not after the third.',
                'no_old_version_running' => 'By the time you swap the columns, no application version that still writes the old one is running anywhere — not on a worker, not on a scheduler, not on an instance somebody forgot to restart.',
            ],
        ],
        'deploy_window_drop' => [
            'release_without_it' => 'First ship a release that no longer reads or writes it — models, queries, serializers, exports, the report nobody has opened since spring. Nothing about the schema changes in this step, and that is the point: the object stays there, unused, while the old version is still allowed to be running.',
            'observation_window' => 'Then wait, and check. "We shipped the code" and "nothing uses it any more" are different claims, and the second is the one that fails: a queue worker still on the old release, a scheduler that was never restarted, a cached container image. How long is your call — long enough that every process which could hold the old version has been replaced.',
            'drop_in_a_later_release' => 'Now run the drop, in a migration of its own, in a LATER release. It is the same statement that was flagged. Nothing has made it safer — what changed is everything that happened before it.',
            'record_the_review' => 'If the drop is deliberate and the window has passed, say so on the migration. This does NOT silence the rule: the finding is still produced and the attribute turns it into a named suppression with your reason attached, visible in the report. Recording the decision is what it is for, and it is not a way past the check.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. Whether the old version is really gone is not something SQLens can check: it reads your migrations, not your running processes.',
            'precondition' => [
                'data_is_expendable' => 'The data really is expendable. This sequence protects the DEPLOY, not the rows: once the drop runs, what was in there is gone, and no ordering fixes that. If you might want it back, copy it out first.',
                'release_boundary_available' => 'You can actually ship two releases. Squeezed into one deploy this sequence is the breaking change it was meant to replace — the order is the entire fix.',
            ],
        ],
        'explicit_identifier' => [
            'name_it_explicitly' => 'Give the object a name of your own. Laravel derives one only when you do not pass one, so a second argument takes the length out of the schema builder\'s hands entirely — and the name you pick can say what the index is for, which the derived one never did. Nothing else about the migration changes.',
            'postgres_reconcile_the_truncated_object' => 'Then check the databases this migration has ALREADY run against — a development machine, a review app, staging. PostgreSQL did not refuse the long name, it truncated it and carried on, so those databases hold the object under the shortened name. Renaming it here does not rename it there: the next deploy creates a SECOND object beside the first. Drop the truncated one, or rename it, before this migration reaches them.',
            'mysql_nothing_was_created' => 'Then move on — there is nothing to reconcile. MySQL refused the statement outright, so no database anywhere holds a partially applied version of it. This is the one thing the two engines do differently here, and it is worth knowing: the PostgreSQL advice about an already-created object does not apply to you.',
            'precondition' => [
                'the_name_is_free' => 'The name you choose is not already taken. Index and constraint names are unique per schema on PostgreSQL and per table on MySQL, so a short name borrowed from another object trades one failing deploy for another.',
            ],
            'verification' => 'Run the migration against a scratch database and read back the object\'s name — `\\d` in psql, `SHOW CREATE TABLE` in MySQL. The name you passed is the name that should come back. On PostgreSQL, confirm the run produced no `NOTICE ... will be truncated`: that message is the only signal it gives, and it does not fail the statement.',
        ],
        'timeout_preamble' => [
            'lock_timeout' => 'Put this in front of the statement that takes the lock. It caps how long the statement waits IN THE LOCK QUEUE — which is what stops one blocked migration from piling every later query for that table up behind it. SET LOCAL scopes it to the migration\'s own transaction, so it cannot leak into whatever the connection does next; a migration that runs outside a transaction (a concurrent index build) uses the plain SET.',
            'statement_timeout' => 'Put this in front of the statement too. It caps how long the statement RUNS once it holds its lock — a different failure from waiting for one, on a different axis, which is why it is a separate line and a separate finding.',
            'retry_rather_than_raise' => 'Decide what happens when it times out, before it does. A timeout does not make the migration succeed; it makes it fail FAST, which is only an improvement if somebody has decided what comes next. Retry the deploy when the table is quieter. The instinctive answer — raise the value — gives back exactly the unbounded wait the setting was added to remove.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. What the preamble is worth on the day is not something SQLens can check: it reads migrations, not your lock queue.',
            'precondition' => [
                'deploy_can_retry' => 'The deploy can be run again safely. A migration bounded by a timeout will sometimes stop halfway through the set, and a pipeline that cannot repeat it turns a fast failure into a stuck one.',
                'value_is_a_decision' => 'The value is yours to pick, and SQLens deliberately offers none. A right lock_timeout depends on how long the busiest transaction on that table runs and on how much deploy window you have — neither of which is in the migration. What SQLens sets on its own read-only session says nothing about what a deploy should.',
            ],
        ],
        'mysql_timeout_preamble' => [
            'lock_wait_timeout' => 'Put this in front of the statement that alters the table. It caps how long the statement waits for the METADATA lock, which is what stops one blocked migration from holding up every reader of that table — MySQL grants those locks in order, so a query that only wanted to read still queues behind a stuck ALTER. MySQL has no SET LOCAL, so this is SET SESSION and the value stays for the rest of the connection; set it deliberately rather than assuming it ends with the migration.',
            'retry_rather_than_raise' => 'Decide what happens when it times out, before it does. A timeout does not make the migration succeed; it makes it fail FAST, which is only an improvement if somebody has decided what comes next. Retry the deploy when the table is quieter. The instinctive answer — raise the value — gives back exactly the unbounded wait the setting was added to remove, and the default here is already a year.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. What the preamble is worth on the day is not something SQLens can check: it reads migrations, not your lock queue.',
            'precondition' => [
                'deploy_can_retry' => 'The deploy can be run again safely. A migration bounded by a timeout will sometimes stop halfway through the set, and a pipeline that cannot repeat it turns a fast failure into a stuck one.',
                'session_scope_is_understood' => 'You accept that the value outlives the migration on this connection. MySQL has no statement-scoped form of this setting, so a preamble set here applies to whatever the connection does next — which is usually what you want during a deploy and rarely what you want on a pooled application connection.',
            ],
        ],
        'batched_backfill' => [
            'split_from_the_schema_change' => 'Move the data write into a migration of its own, and let the schema change commit first. Batching a write that still shares the schema change\'s transaction fixes nothing: the exclusive lock is held until commit, so every batch — and every pause between batches — happens under it. That is a slower outage, not a shorter one. This step is what makes the three below help rather than hurt.',
            'timeout_per_batch' => 'Bound the job connection\'s statement timeout to ONE BATCH, not to a whole migration. A value carried over from a migration preamble is far too generous here — it will let a single runaway batch hold locks for minutes, and far too strict values will abort a backfill that was working perfectly.',
            'job' => 'Move the write into a queued job and page by the last key you saw, never by OFFSET. With OFFSET the server walks and discards the rows it already handled, so batch number k costs more than batch k-1 — the last batch of a long backfill is the most expensive one, exactly when nobody is watching any more. Keyset paging is an index seek every time, and it survives an interruption because the resume point is a value rather than a position in a result set that has since changed.',
            'resume_criterion' => 'Decide, before you start, how you would resume it. The job must be safe to run twice over the same rows and safe to stop between batches — that is what turns "the deploy timed out" into "we continue tomorrow" instead of "we do not know how far it got".',
            'verification' => 'Run sqlens:lint again — the migration must no longer carry the write. The job itself is outside what SQLens can check: it reads migrations, not your queue.',
            'precondition' => [
                'orderable_key' => 'The table has a stable, orderable key to page by — usually the primary key. Without one, keyset paging can skip rows or return them twice, and neither shows up as an error.',
                'idempotent_write' => 'The write is safe to repeat. A batch that is retried after a timeout must not double anything, or the recovery is worse than the original problem.',
                'size_is_an_estimate' => 'Any row count you have seen from SQLens is an ESTIMATE read from catalog statistics. It is good enough to say a table is large and never good enough to pick a batch size — measure that, or start small.',
            ],
        ],
        'expand_contract' => [
            'expand' => 'Add the new column beside the old one — nullable and with no default, which on a current PostgreSQL or MySQL is a metadata change rather than a rewrite. Nothing reads it yet, so this phase ships in an ordinary deploy.',
            'backfill' => 'Move the data across from a queued job, in bounded batches. Not from the migration: the work has no bound in time, and a migration holding a transaction open for it is the incident this whole sequence exists to avoid. The batching recipe is its own strategy — follow that one rather than inventing a loop here.',
            'dual_write' => 'Ship a release that writes BOTH columns and reads the new one, and leave it running for at least one full release. This is the phase that makes the last step safe: until every running instance has stopped using the old column, dropping it breaks whatever is still there.',
            'contract' => 'Drop the old column — in a migration of its own, in a LATER release, never this one. If the previous phase has not actually completed, this is the statement that causes the outage.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. Between the first and the last phase the old column is still standing, and that gap is what SQLens accounts for: a sequence that stops after the expand looks finished and never is.',
            'contract_only' => 'Drop the column the new one replaced — in a migration of its own. The expand and the back-fill already happened, so this is the only statement left; adding the column again would fail, and the migration that added it is not yours to edit any more.',
            'debt_until_contracted' => 'Until that migration ships, the table carries two columns for one fact and nothing in the schema says which is authoritative. SQLens keeps the account open and ages it, so an end left open for months is visible as one rather than as an old finding nobody re-read.',
            'precondition' => [
                'no_old_version_running' => 'By the time you reach the last phase, no application version that still knows the old column is running anywhere — not on a worker, not on a scheduler, not on an instance somebody forgot to restart.',
                'release_boundary_available' => 'You can actually ship two releases. This sequence spans a release boundary by design; squeezed into one deploy it is the breaking change it was meant to replace.',
            ],
        ],
        'concurrently' => [
            'timeout_preamble' => 'Put the timeout preamble in front of the statements below. Bounding how long a statement waits is what keeps a concurrent build from sitting behind a long transaction — and it is also what can abort one, so read this together with the INVALID sweep at the end.',
            'separate_migration' => 'Move the statement into a migration of its own and switch that migration\'s transaction off with the snippet below. Laravel wraps up() in a transaction on PostgreSQL, and CONCURRENTLY refuses to run inside one — without this line the fix fails on its first deploy.',
            'create_index' => 'Build the index concurrently, in the migration you just created. It takes longer than the ordinary form and does not block writers while it runs.',
            'sweep_invalid' => 'If the build is interrupted, PostgreSQL leaves an INVALID index behind under the same name — and the name is then taken, so a straight re-run fails on the conflict instead of on the original problem. Check for one, drop it concurrently, then run the migration again.',
            'drop_index' => 'Drop the index concurrently, in the migration you just created. It removes one index per statement.',
            'retry_drop' => 'If the drop is interrupted, the index stays behind marked dead and is no longer used for queries. Run the same drop again to clear it.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. After the deploy, sqlens:postdeploy is what catches an index left INVALID by an interrupted build.',
            'precondition' => [
                'no_leftover_index' => 'No index of this name exists yet. An earlier interrupted attempt leaves one behind, and the name has to be free before the build starts.',
                'index_unused' => 'Nothing depends on the index any more: no constraint backed by it, and no query plan you still need it for.',
                'migrator_leaves_transaction' => 'The deploy can run a migration outside a transaction — the sequence below needs that, and a migrator that wraps everything cannot give it.',
            ],
        ],
        'constraint' => [
            'add_not_valid' => 'Add the constraint NOT VALID. It applies to every new row from that moment and costs a brief metadata lock instead of a scan of the whole table — the lock a foreign key would otherwise hold on the referenced table as well.',
            'not_null_check' => 'Add a CHECK that says what you are about to enforce, unvalidated. It costs a brief metadata lock and applies to every new row at once.',
            'validate' => 'Validate it in a migration of its own, on a later deploy. That scan runs under a SHARE UPDATE EXCLUSIVE lock, which does not block reads and writes.',
            'set_not_null_trusts_it' => 'Now set the column NOT NULL. Since PostgreSQL 12 it TRUSTS the validated check and skips reading every row — which is the whole point of the two steps in front of it. Without them this statement is the full-table scan under an ACCESS EXCLUSIVE lock that was reported.',
            'drop_the_now_redundant_check' => 'Then drop the check. The column itself carries the guarantee now, and leaving both means every write is verified twice.',
            'debt_until_validated' => 'Between those two steps the constraint does not hold for the rows that were already there, and the planner will not rely on it. Nothing breaks and nothing is slow, which is exactly why this is the step that gets forgotten — so SQLens keeps it as an open debt until the validation lands.',
            'build_index_concurrently' => 'Build the unique index first, concurrently, in a migration of its own. PRIMARY KEY and UNIQUE do not accept NOT VALID: they are implemented with an index, so the index has to exist before the constraint can be put on it. Everything the concurrent build needs applies here too, including the cleanup for an interrupted one.',
            'promote_index' => 'Promote the finished index onto the constraint. That is a metadata change — the index is already built, so there is no validating scan.',
            'index_must_be_valid' => 'Check that the index came out VALID before you promote it. An interrupted concurrent build leaves an INVALID one behind, and promoting that fails.',
            'verification' => 'Run sqlens:lint again — the rule must no longer report this migration. On the server, sqlens:predeploy is what finds a constraint that was added NOT VALID and never validated.',
            'precondition' => [
                'existing_rows_may_violate' => 'Rows that are already there may violate the constraint. NOT VALID accepts them; step two is where that comes out, so look at the data before you plan the second deploy.',
                'no_null_rows' => 'No existing row is null in that column. If one is, step two fails — which is better than step three failing, but it is still a failure you want to meet on your own schedule rather than during a deploy.',
                'second_migration_is_planned' => 'The second migration is planned, not merely intended. An unvalidated constraint is a state this sequence passes through, never one it ends in.',
                'no_duplicate_rows' => 'No duplicate rows exist on those columns. The concurrent build is where a duplicate surfaces, and it surfaces as a failed build rather than as a clear sentence about your data.',
                'migrator_leaves_transaction' => 'The deploy can run a migration outside a transaction — the concurrent build needs that, and a migrator that wraps everything cannot give it.',
            ],
        ],
    ],
];
