<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Security\OriginBinding;

/**
 * The named reasons a check can be undetermined. "No silent green" means an
 * undetermined result is never anonymous — every one points at a reason from
 * this list, each derived from a concrete pitfall in the plan.
 *
 * The backed string values reach the JSON output, so they are stable public API
 * from 1.0 on.
 */
enum UndeterminedReason: string
{
    case MissingPrivilege = 'missing_privilege';
    case ServerUnreachable = 'server_unreachable';
    case UnknownServerVersion = 'unknown_server_version';
    case PretendLimit = 'pretend_limit';
    case UnsupportedEngine = 'unsupported_engine';
    case MissingExternalTool = 'missing_external_tool';
    case ManagedDatabaseRestriction = 'managed_database_restriction';
    /**
     * An external tool reported a finding under a rule this build's map does not describe.
     *
     * The shape a NEW tool version takes: it grows a rule, and every pipeline that upgraded the
     * binary would otherwise see a finding appear out of nowhere, at a level and category nobody
     * chose. Reported as undetermined with the rule named, so it is visible and does not silently
     * become a failure somebody else's build has to explain.
     */
    case ToolRuleUnmapped = 'tool_rule_unmapped';

    /**
     * An external tool's finding could not be placed on a statement.
     *
     * A finding without a location is not actionable, and the tempting alternative — attributing
     * it to the first statement — is worse than saying nothing: it reads as a real finding on the
     * wrong line, and the baseline written from it moves the next time the file changes.
     */
    case ToolPositionUnmappable = 'tool_position_unmappable';
    case StructurallyNotApplicable = 'structurally_not_applicable';

    /**
     * The engine is supported and its VERSION is not: the server — or the pinned version the
     * run reasons from — is below the floor this driver's rules were written for.
     *
     * Deliberately NOT `unsupported_engine`. That reason means "SQLens will never reason about
     * this engine", and its only fix is to stop pointing SQLens at it; this one means "upgrade,
     * and until then read the report as advisory". A pipeline branching on the reason has to be
     * able to tell a dead end from a deadline.
     */
    case ServerBelowSupportedFloor = 'server_below_supported_floor';

    /**
     * The catalog read hit its OWN time budget — the reader's bound, not the database's fault.
     *
     * Distinct from a server timeout on purpose: this package sets that bound itself, and filing its
     * own self-restraint as a database problem would send somebody looking for a fault that is not
     * there.
     */
    case CatalogReadBudgetExceeded = 'catalog_read_budget_exceeded';

    /**
     * The catalog read failed for a reason nothing anticipated, and the error code travels with it.
     *
     * The catch-all, and deliberately not dressed up as something more specific: an error nobody
     * foresaw is exactly what a named reason cannot describe, and a plausible-sounding wrong label
     * would cost more than an honest unknown.
     */
    case CatalogReadFailed = 'catalog_read_failed';

    /**
     * The statistics reading came back WITHOUT the object a finding names, so it could not be weighed.
     *
     * Distinct from {@see self::StatisticsUnavailable}, and the distinction is the reason this case
     * exists rather than reusing it: that one means a statistics-DEPENDENT rule could not run at all
     * and therefore reached no verdict. Here the rule reached its verdict from the migration text
     * exactly as it does in CI — only the size-weighting on top of it could not happen.
     *
     * The commonest cause is a table nobody has ever run ANALYZE on. PostgreSQL answers `reltuples`
     * with `-1` there, the reader resolves that sentinel into no row count at all, and a row-measured
     * operation has nothing to compare against. A budget that ran out mid-reading produces the same
     * silence for the objects it did not reach.
     *
     * ## Why the absence is reported at all
     *
     * Because nothing else would say it. The finding stands at the severity lint gave it, which is a
     * correct verdict, and a reader looking at a predeploy report has no way to tell "this table is
     * small" from "nobody could measure this table". Those are different facts and one of them is a
     * reason to go and run ANALYZE before deploying.
     */
    case ObjectStatisticsUnread = 'object_statistics_unread';

    /**
     * The debt ledger declares a schema version this build cannot act on — or declares none.
     *
     * Never read as an empty ledger, and the asymmetry is the reason it has a code of its own. A
     * file written by a NEWER build may hold entries in a shape this one would drop, which reports
     * a project as owing nothing at the moment it owes the most; a version this build has never
     * seen is not an older dialect to guess at. Both are answered by moving a version — upgrade the
     * tool, or migrate the file — which is why they share one code and one action.
     */
    case DebtLedgerSchemaUnsupported = 'debt_ledger_schema_unsupported';

    /**
     * The debt ledger file exists and is not a ledger: malformed JSON, or a shape with no entries.
     *
     * A separate code from the version above because the fix is a different one — repair the file
     * from version control, or delete it and start an account deliberately. A file nobody can parse
     * is not a project without debts, and reading it as one is exactly the silent green this
     * package refuses.
     */
    case DebtLedgerUnreadable = 'debt_ledger_unreadable';

    /**
     * How long a debt has been outstanding could not be established.
     *
     * Two ways in, and both are real rather than hypothetical: the recorded `first_seen` is not a
     * date this build can read, or it lies AFTER the instant the run measures against — a machine
     * with a skewed clock, or a hand-edited ledger.
     *
     * Neither is rounded away, and the direction is why. Clamping an unreadable or future date to
     * zero reports the debt as recorded today, so a debt that has been outstanding for a year would
     * look brand new on every single run — the reassuring answer, and the one that makes the whole
     * account useless.
     */
    case DebtAgeUnknown = 'debt_age_unknown';

    /**
     * A recorded debt names an object the catalog does not show.
     *
     * Deliberately not read as "settled". A dropped table, a schema outside this run's scope and a
     * role without the privilege to see it all look exactly like this, and each is a different
     * thing to go and check — reporting any of them as a paid debt would remove an entry on the
     * strength of an absence.
     */
    case DebtObjectNotFound = 'debt_object_not_found';

    /**
     * The debt account was expected here and is not on disk.
     *
     * The COLLECTING side's answer, and the opposite of the recording side's. A repo run may treat
     * an absent file as an empty account — nothing has been recorded yet. A run that reads one on a
     * deploy server may not: the file not being deployed, or `deploy.debt.path` pointing at the
     * wrong working directory, is exactly the likely case, and "no open debts" would be the most
     * comfortable possible wrong answer.
     */
    case DebtLedgerMissing = 'debt_ledger_missing';

    /**
     * No Eloquent model in this application maps to the table a column belongs to.
     *
     * Never read as "so the column is unprotected". Whether a column is encrypted is a fact about
     * the MODEL, and a catalog that shows the column while no model claims the table means the
     * question was never reachable — a table owned by another service, a model outside the
     * conventional directory, or a project that maps tables some other way.
     *
     * Reporting it as unprotected would put a `critical`-shaped claim on the one thing this package
     * demonstrably did not look at.
     */
    case ModelNotFound = 'model_not_found';

    /**
     * A model class maps to the table and could not be constructed.
     *
     * Distinct from {@see self::ModelNotFound}, and the distinction is what a reader acts on: the
     * first says "look for a model", the second says "this model is broken or needs something the
     * inspection cannot give it". A constructor that reaches for a container binding, a trait boot
     * that touches a service, an abstract class picked up by the scan — all land here, and each is
     * a different thing to go and fix.
     */
    case ModelNotConstructible = 'model_not_constructible';

    /**
     * The model's cast list is not the same on two constructions.
     *
     * `casts()` is a method, so it may read anything — a request, a tenant, a feature flag. A list
     * that changes between two fresh instances describes no fixed schema fact, and freezing whichever
     * one happened to be built first would make the finding depend on the order a run walked the
     * models in.
     *
     * Measured rather than assumed: the reading constructs twice and compares.
     */
    case ModelCastsNotStatic = 'model_casts_not_static';

    /**
     * The column is cast through a custom castable class, which may or may not encrypt.
     *
     * The case that decides whether this whole family is honest. `'ssn' => \App\Casts\Encrypted::class`
     * is an ordinary way to encrypt a column and is indistinguishable, from the outside, from a class
     * that does nothing of the sort — the package would have to execute somebody's cast to find out,
     * which it will not do.
     *
     * Reporting it is a false positive on the loudest rule in the suite; passing it is a silent green.
     * Neither is available, so it is named.
     */
    case CustomCastOpaque = 'custom_cast_opaque';

    /**
     * Two models map to the same table and disagree about a column's cast.
     *
     * A legitimate arrangement — single-table inheritance, a read model beside a write model — and
     * the package has no basis for preferring one. Taking the encrypted answer would hide a real gap;
     * taking the unencrypted one would invent a finding against a column that is protected on the
     * path that matters. The disagreement is the fact, so the disagreement is what is reported.
     */
    case ConflictingModelCasts = 'conflicting_model_casts';

    /**
     * The column stores raw bytes, and raw bytes are what server-side encryption leaves behind.
     *
     * Measured on PostgreSQL: a column pgcrypto wrote and a column holding an avatar are BOTH
     * `bytea`, and nothing in the catalog separates them — the type is simply what the engine uses
     * for bytes. MySQL's `blob` family says exactly as little.
     *
     * So encryption applied at the SERVER is something this package can let SUPPRESS a finding and
     * can never use to RAISE one. A binary column with no Eloquent cast is therefore not "stored in
     * the clear": it is a column whose protection lives somewhere this reading cannot see.
     *
     * Reporting it would be a false positive on the loudest rule in the suite, against a column that
     * may be the best-protected one in the schema. Passing it would be a silent green over one that
     * is not. Neither is available, so it is named.
     */
    case OpaqueBinaryColumn = 'opaque_binary_column';

    /**
     * A preflight check asked who OWNS an object and the catalog answered with no row at all.
     *
     * `ALTER` and `DROP` cannot be granted on PostgreSQL — they require ownership, so the question is
     * membership in the owning role rather than a privilege. When that question comes back empty the
     * cause is not a refusal: it is the object having disappeared between the existence probe and the
     * ownership probe, or the connecting role not being able to read the catalog row that names the
     * owner.
     *
     * Its own reason because a reader acts differently on each. "The server refused the question" is
     * a privilege problem on the CATALOG; "nobody could establish the owner" is a race, or a role
     * that cannot see `pg_class` at all. Both used to arrive as the same sentence in the same free-text
     * field, which meant a consumer could count neither.
     *
     * Never a pass: answering `true` would certify a permission nobody checked, and answering `false`
     * would send somebody to grant something that is not grantable.
     */
    case OwnershipUnreadable = 'ownership_unreadable';

    /**
     * The role the migrations run as does not exist on this server.
     *
     * Its own reason rather than a line inside "the server refused the privilege question", because
     * the two send a reader to opposite places. A refused privilege question is about GRANTS; this
     * is almost always a typo in the connection's `username`, or a role that exists on staging and
     * was never created here — and somebody told the first thing spends the afternoon reading ACLs.
     *
     * Never a pass, and never a fail either. A role that does not exist has no privileges, so
     * reporting every requirement as missing would be technically true and useless: the deploy is
     * not short of a grant, it is pointed at nobody.
     */
    case MigrationRoleMissing = 'migration_role_missing';

    /**
     * A table prefix is configured and nothing in the audited schemas carries it.
     *
     * The likeliest cause is a prefix copied from another project, or read from a connection the
     * application does not use — so the audit examined nothing, and an audit of nothing must never
     * read like an audit of a clean schema.
     */
    case ConfiguredPrefixMatchedNothing = 'configured_prefix_matched_nothing';

    /** The host application defines no connection under the requested name. */
    case ConnectionNotConfigured = 'connection_not_configured';

    /**
     * A check needs a setting the project has not made, and guessing it would be worse than silence.
     *
     * Distinct from {@see ConnectionNotConfigured}, which is a name that resolves to nothing: this is
     * a question nobody has answered yet. The least-privilege check is the case it exists for — SQLens
     * cannot tell which of a project's connections serves requests, and naming the wrong one would
     * send somebody to revoke a privilege their deploy depends on.
     */
    case NotConfigured = 'not_configured';

    /**
     * A pinned host could not be checked against the one the server named.
     *
     * The pin took effect at the driver — that much is certain, it was written onto the connection
     * this run built. What could not be established is that the machine which answered is the
     * machine that was named, because a name and an address do not compare and resolving one would
     * put a DNS lookup, and a second source of truth, inside a run that promises determinism.
     *
     * Reported rather than swallowed: a run that never verified the pin and a run that verified it
     * happily produce identical findings, and the reader has to be able to tell them apart.
     */
    case PinnedHostUnverifiable = 'pinned_host_unverifiable';

    /**
     * A setting was read through a connection that multiplexes statements across server backends.
     *
     * The values come back looking entirely ordinary, and that is the danger: the "global" half of a
     * reading may describe one machine and the "session" half another, so the distinction every
     * server-baseline rule rests on stops meaning anything. Reported as a named gap instead of
     * judged, because a plausible answer assembled from two servers is worse than no answer.
     */
    case TransactionPooled = 'transaction_pooled';

    /**
     * No pin was set and the addressed connection produced no readable version — the
     * ordinary shape of a run with nothing to ask, such as the single-file fast path.
     *
     * It is kept apart from {@see UnreadableServerVersionPin} because the two need
     * opposite advice. This one is fixed by SETTING assume_server_version; that one is
     * fixed by CORRECTING it. Reported under one reason, a project that pinned a typo
     * would be told to add the pin it already has, and would keep reading the message
     * as the fast path's normal noise.
     */
    case ServerVersionUnresolvable = 'server_version_unresolvable';

    /**
     * A column's type change names a target type this build's type-change matrix does
     * not classify, so whether it rewrites the table could not be decided. The static
     * path cannot see the source type, so an unlisted target is genuinely unknown rather
     * than assumed safe — reported, never a silent pass.
     */
    case UnclassifiedTypeChange = 'unclassified_type_change';

    /**
     * `assume_server_version` is set but cannot be read as a version.
     *
     * There is deliberately no fall-through — not to the detected version, and not to
     * the supported baseline. Falling back would make a typo in the pin behave exactly
     * like a run that never pinned anything, which is the failure the pin exists to
     * prevent: a project that believes it audits deterministically against a named
     * version, while every run silently reasons about whatever it found instead.
     */
    case UnreadableServerVersionPin = 'unreadable_server_version_pin';

    /**
     * The run reasoned about an ASSUMED server version (a pin) that disagreed with
     * the version the connected server actually reported. The result reflects the
     * pin, not the live instance, so the verdict against the real server is
     * undetermined — reported, never silently trusted, so the drift is visible.
     */
    case AssumedVersionSkew = 'assumed_version_skew';

    /**
     * A migration file could not be read as PHP, so the static pre-scan could not
     * look inside it. Never "no hits, therefore clean" — a file the scanner cannot
     * parse is a file whose side effects it also cannot see.
     */
    case UnparsableMigration = 'unparsable_migration';

    /**
     * A captured statement could not be substituted or canonicalized into the
     * one form a rule is allowed to read. The raw grammar output is never passed
     * through in its place — a rule matching on formatting instead of on SQL is a
     * silent, invisible wrongness — so the migration is undetermined with the
     * specific reason named.
     */
    case UncanonicalizableStatement = 'uncanonicalizable_statement';

    /**
     * A rule that means different things in different places could not tell WHERE this statement
     * came from.
     *
     * The path-bound rules — a password literal is Critical in a migration and nothing at all in a
     * seeder — need the origin to decide, and the fast path can be handed a snippet with no file
     * behind it at all. Neither of the two confident answers is available then, and both are wrong
     * in a way nobody would see: `pass` hides a real leak, and a Critical fires on evidence the run
     * does not have.
     *
     * So the third answer is named. {@see OriginBinding::Unknown} is what
     * produces it.
     */
    case OriginUnknown = 'origin_unknown';

    /**
     * The server stored an EXPANDED form of what a migration wrote, and the original is gone.
     *
     * The case it exists for is `SELECT *` in a view. Both engines resolve the star to a fixed
     * column list when the view is created and keep only the result — measured on PostgreSQL 18.4
     * (`pg_get_viewdef` returns `SELECT a, b FROM t`) and MySQL 8.4.10 (`VIEWS.VIEW_DEFINITION`
     * returns the same thing with every column qualified). Re-reading after a column is added
     * returns the same two columns, which is exactly the defect and also the reason it is invisible
     * afterwards.
     *
     * So a catalog check cannot answer whether the view was written with a star, and the two
     * confident answers are both wrong: `pass` says a view was checked and is clean when nothing
     * was checked, and `fail` accuses a view whose author named every column. The honest answer
     * names where the question CAN be answered — the migration, in the lint suite.
     *
     * It is not {@see self::MissingPrivilege} or {@see self::CatalogReadFailed}: the read succeeded
     * and the privilege was there. The information was destroyed before it ever reached the
     * catalog, so no amount of access would recover it.
     */
    case ServerExpandedDefinition = 'server_expanded_definition';

    /**
     * An object's NAME looks like a transition leftover, and a name is not evidence.
     *
     * `users_old`, `tmp_backfill_state`, `orders_20260721` — every one of those is what an abandoned
     * expand/contract migration leaves behind, and every one of them is also a perfectly reasonable
     * name for a table somebody meant to keep. The catalog holds nothing that separates the two.
     *
     * So a pattern match is reported at this rung and never as a failure. The distinction is the
     * whole value of the check: `pass` would hide real wreckage, and `fail` would accuse an archive
     * a team queries every quarter — and the first false accusation on a table people rely on is the
     * last time anybody reads the report.
     *
     * What turns it into a decided answer is a second, independent reading: the object appearing in
     * no migration state at all. Until that exists, the honest answer is that the name looks like
     * one and the check cannot tell.
     */
    case NameSuggestsTransitionObject = 'name_suggests_transition_object';

    /**
     * A rule that must know where a VALUE came from could not tell.
     *
     * Separate from {@see self::OriginUnknown} deliberately, and the separation was earned: both
     * questions arise in the same rule and both were reported under one reason, which made a report
     * unable to say which of two different problems it had met — and made the author of this rule
     * unable to tell, either, while debugging its own fixture.
     *
     * They also have different remedies. An unknown STATEMENT origin means the run had no file to
     * attribute the statement to. An unknown VALUE origin means the capture never learned whether
     * the literal in the text was typed there or supplied at the call site, which is a different
     * gap in a different layer.
     */
    case ValueOriginUnknown = 'value_origin_unknown';

    /**
     * The static pre-scan flagged this migration before it was captured — a side
     * effect it would fire, a query result it depends on, an introspection guard
     * pretend cannot see past, or a call into code the scan cannot follow. The
     * migration is not pretend-executed at all; the specific hits carry the line
     * and the resolution, and shadow mode is the truth mode that can answer.
     */
    case PreScanFlagged = 'prescan_flagged';

    /**
     * The run's active rule set was empty because a filter — the category filter or
     * the level gate — removed every rule that would have run. Never a pass: a run
     * that checked nothing is not a run that found nothing, so the emptiness is named
     * rather than reported as clean. The remedy is to widen the `--category`/`--level`
     * selection or to accept that the requested scope has no rules yet.
     */
    case NoActiveRules = 'no_active_rules';

    /**
     * The run resolved its subject set and the set was EMPTY — no migration was judged.
     *
     * Its own reason rather than {@see self::NoActiveRules}, because the two send a reader to
     * opposite places: there the rules were filtered away over real migrations, here there were
     * rules and nothing to apply them to. And not a pending-SKIP reason either, because nothing
     * failed to resolve — the answer is known and it is zero. (Named in prose rather than with a
     * `{@see}`: the capture layer already imports THIS enum, and a reference back would make the
     * two files cite each other for a docblock's sake.)
     *
     * The state that produces it is the ordinary one, which is why it needed naming: `--path` lints
     * the PENDING migrations, and on any machine where `migrate` has already run nothing is pending.
     * A pipeline that lints after its migration step therefore hangs the check exactly where it can
     * no longer see anything, and the run before this existed said `over 0 migrations` and exited 0.
     */
    case NoMigrationsRead = 'no_migrations_read';

    /**
     * A rule that reasons about the server's table statistics ran with statistics
     * turned on (`use_statistics`), but no statistics reader is available in this
     * build to answer it — the reader arrives with the audit suite. "Could not read
     * the statistics" and "the statistics say you are fine" are different results, so
     * the check is a named undetermined, never a silent pass. With `use_statistics`
     * off, such a rule does not run at all, which is a deliberate scope, not a skip.
     */
    case StatisticsUnavailable = 'statistics_unavailable';

    /**
     * The shadow capture mode was blocked from running — the production guard
     * refused it (a disallowed environment, a production connection, or a missing
     * confirmation). A blocked run is never a pass: nothing was captured, and the
     * reason names why the guard held it.
     */
    case ShadowGuardBlocked = 'shadow_guard_blocked';

    /**
     * The target of a database-creating mode is a read replica (PostgreSQL in
     * recovery, MySQL read-only). A replica has a different state than its primary
     * and cannot be provisioned against, so the run is not attempted — never run
     * against the wrong instance and call it captured.
     */
    case TargetIsReplica = 'target_is_replica';

    /**
     * The rule's verdict is scoped to the instance and its write path, and the
     * instance that answered is not on it — a replica, or one whose role could not
     * be established at all. Distinct from {@see self::TargetIsReplica}, which is
     * about a database-creating mode refusing to provision: here the run proceeds
     * and reads normally, and it is the SELECTION of rules that narrows, because a
     * server setting read on a replica describes the replica rather than the system.
     * An unestablished role withholds exactly as a replica does — a verdict nobody
     * can place is worth as much as one placed on the wrong machine.
     */
    case InstanceScopeUnanswerable = 'instance_scope_unanswerable';

    /**
     * A UUID primary key carries no server-side default, so who generates the value
     * — the application or the server — could not be read from the catalog. The
     * distinction decides whether a recommendation applies at all, and guessing it
     * would put advice in front of somebody about code the tool never saw. Laravel
     * generates UUIDs in the application by default, which is precisely why the
     * absence of a server default is uninformative rather than telling.
     */
    case UuidGenerationUnknown = 'uuid_generation_unknown';

    /**
     * A table was read, but the character set or collation it stores text under
     * came back empty. MySQL reports neither for a table whose storage engine has
     * no concept of them, and the reader keeps an absent attribute absent rather
     * than substituting a plausible default. "Nobody could read the encoding" and
     * "the encoding is fine" are different statements, and only a rule that keeps
     * them apart can be trusted the one time it matters.
     */
    case TextEncodingUnknown = 'text_encoding_unknown';

    /**
     * A question that spans two objects could not be answered, because the second
     * one is outside the audited scope. A foreign key pointing at a table in a
     * schema this run was not asked to read is the ordinary shape: the edge is
     * real, the near side is known, and the far side is simply not there to
     * compare against. Reported rather than skipped, because an edge nobody
     * followed and an edge that matched look identical from inside the schema
     * that was read — and widening the scope is a fix somebody can act on.
     */
    case ReferencedObjectNotInScope = 'referenced_object_not_in_scope';

    /**
     * Whether a unique index counts two NULLs as the same value could not be
     * read. It decides the verdict outright: PostgreSQL 15 added
     * `UNIQUE … NULLS NOT DISTINCT`, and a key declared that way holds across
     * its nullable rows while an otherwise identical one does not. Reporting
     * without the flag would punish the schema that already applied the fix —
     * the most expensive false positive a rule can produce — and passing would
     * claim a constraint nobody verified.
     */
    case UniqueNullTreatmentUnknown = 'unique_null_treatment_unknown';

    /**
     * A column draws from a sequence it owns, but through a default that is not
     * the shape `serial` produces — `COALESCE(nextval('s'), 1)` rather than the
     * bare call. Both readings would be wrong: an identity column cannot express
     * a wrapped default, so advising the conversion would quietly change what the
     * column defaults to, and staying silent would report a schema as checked
     * where the one question worth asking went unanswered.
     */
    case SequenceOwnershipUnclear = 'sequence_ownership_unclear';

    /**
     * How long the server has been counting index scans could not be
     * established — the statistics view was unreadable, or the counters have
     * never been reset and so cover a window starting at a moment nobody
     * recorded. A zero count over an unknown window is not evidence of
     * anything, and reporting it as one would advise dropping an index on the
     * strength of a number whose age nobody knows. The opposite reading is no
     * better: a table whose indexes are genuinely unused and a role that could
     * not see the view produce the same empty answer.
     */
    case IndexUsageWindowUnknown = 'index_usage_window_unknown';

    /**
     * A shadow session hit one of its own timeouts — a statement, a lock, or an
     * idle transaction took longer than the bounded budget. The tool bounds its
     * own sessions so a shadow run never sits on the source instance holding
     * resources; a budget it hit is a named result, never a passed-through
     * exception and never a pass.
     */
    case ShadowSessionTimeout = 'shadow_session_timeout';

    /**
     * The shadow target sits behind a transaction pooler (PgBouncer in
     * transaction mode), where `CREATE DATABASE … TEMPLATE` and the other template
     * operations the shadow mode needs cannot run. Detected heuristically before
     * any DDL is issued: rather than try and fail, the run stops and asks for a
     * direct connection under `capture.shadow.direct_connection`.
     */
    case ShadowTransactionPooling = 'shadow_transaction_pooling';

    /**
     * `capture.shadow.direct_connection` names a connection on a DIFFERENT server than the one under
     * examination. That setting exists to reach the same server around a transaction pooler, so a
     * different one would create and drop databases on an instance the run never named. Detected
     * BEFORE any DDL, from configuration alone — no connection is opened to find out.
     */
    case ShadowDirectConnectionElsewhere = 'shadow_direct_connection_elsewhere';

    /**
     * The role provisioning would connect as lacks the privilege to create a
     * database (PostgreSQL `CREATEDB`). Checked BEFORE any `CREATE DATABASE` is
     * attempted, so a role that cannot provision is a named result, never a raw
     * permission error mid-run — and never a silent pass.
     */
    case ShadowInsufficientPrivileges = 'shadow_insufficient_privileges';

    /**
     * The template database has other active connections, which PostgreSQL forbids
     * for `CREATE DATABASE … TEMPLATE`. Detected by reading `pg_stat_activity`
     * before the clone, so a busy template is a named result the user can act on,
     * never a failed template operation.
     */
    case ShadowTemplateInUse = 'shadow_template_in_use';

    /**
     * ONE object type, on ONE side of the drift comparison, could not be read — so that slice of the
     * schema was never compared.
     *
     * Distinct from {@see self::CatalogReadFailed}, and the distinction is the whole reason this
     * case exists rather than reusing it: that one says a catalog reading failed. This one says a
     * reading SUCCEEDED and is incomplete, which is the more dangerous of the two — a comparison
     * that could not see indexes and reported no index drift has stated something false, and
     * nothing about the run looks wrong.
     */
    case DriftSideUnreadable = 'drift_side_unreadable';

    /**
     * A database with the generated shadow name already exists. The run stops
     * rather than touch a database it did not create — the shadow mode only ever
     * creates and drops databases carrying its own prefix, and never adopts one it
     * finds.
     */
    case ShadowNameCollision = 'shadow_name_collision';

    /**
     * The MySQL shadow mode needs the `schema:dump` artifact to rebuild the
     * throwaway database (MySQL has no `CREATE DATABASE … TEMPLATE`), and the file
     * is missing or unreadable. Never run against an empty database and call it a
     * pass — that is green with nothing behind it; the remedy is `php artisan
     * schema:dump`.
     */
    case ShadowMysqlSchemaDumpMissing = 'shadow_mysql_schema_dump_missing';

    /**
     * The PostgreSQL shadow mode could not read the project's schema definition, so
     * it could not build the empty template a clone is made from. It does not fall
     * back to cloning the live database — that is the harm the template exists to
     * prevent — so the run stops with this reason instead.
     */
    case ShadowPgsqlSchemaDumpMissing = 'shadow_pgsql_schema_dump_missing';

    /**
     * The empty shadow template could not be built — the schema replay failed, or
     * the database could not be inspected afterwards. The half-built database is
     * dropped and nothing is cloned: a template nobody verified is not a template.
     */
    case ShadowTemplateBuildFailed = 'shadow_template_build_failed';

    /**
     * The `schema:dump` artifact could not be split into statements safely — an
     * unterminated literal or an unknown delimiter situation. A half-replayed shadow
     * database is the mode's most dangerous state (green against half a schema), so
     * the run stops with the line named rather than replaying part of the dump.
     */
    case ShadowMysqlDumpUnparseable = 'shadow_mysql_dump_unparseable';

    /**
     * A statement from the `schema:dump` failed while it was being replayed into the
     * throwaway MySQL database. The half-built database is dropped and the run is
     * undetermined — never a lint against a schema that only partially rebuilt.
     */
    case ShadowMysqlReplayFailed = 'shadow_mysql_replay_failed';

    /**
     * An earlier migration failed during the real shadow migrate, so this one was
     * never run: the database is in a partial state and running on top of it would
     * fail or, worse, lint against a schema that never really formed. It is reported
     * as undetermined — not a pass, not empty — while the migration that actually
     * failed carries its own level-0 finding.
     */
    case ShadowMigrateFailed = 'shadow_migrate_failed';

    /**
     * The throwaway shadow database could not be dropped after the run. A database
     * nobody removes is a leak in the user's environment, so a failed drop is
     * surfaced with this reason and the leaked database's name — never a swallowed
     * error. The orphan sweep on a later run is the safety net that removes it.
     */
    case ShadowTeardownFailed = 'shadow_teardown_failed';

    /**
     * The roundtrip reached the `down` leg and the migration defines no `down()` at
     * all, so there is nothing to replay.
     *
     * Treating that as a clean `down` would be the silent green in its purest form:
     * the second `up` would then fail against the schema the first one left, and the
     * run would report `CAP.L0.DOWN_NOT_INVERTIBLE` — blaming an inverse that was
     * never written. "There is no rollback path" and "the rollback path does not
     * invert" are different facts, and only the first one is true here.
     */
    case RoundtripNoDownMethod = 'roundtrip_no_down_method';

    /**
     * What the migration's `up()` brought into existence could not be enumerated, because one
     * of its statements was captured but never classified.
     *
     * The reason a rule comparing `down()` against `up()` has to stop there rather than shrug:
     * an unclassified statement may well be the `CREATE TABLE` that makes a rollback's `DROP
     * TABLE` symmetric. Reading the missing classification as "up() created nothing" would turn
     * the most ordinary migration into a finding; reading it as "nothing to see" would hide the
     * real one. Neither is knowledge, so the run says so.
     */
    case UpStateNotCapturable = 'up_state_not_capturable';

    /**
     * What the migration's `down()` would destroy could not be enumerated: the rollback leg
     * was captured, but one of its statements carries no classification.
     *
     * The mirror of the reason above, kept apart from it because the two send a reader to
     * different files. An unclassified rollback statement may be the `DROP TABLE` the rule
     * exists to catch, and a rule that passed over it would be at its most confident exactly
     * where it saw least.
     */
    case DownStateNotCapturable = 'down_state_not_capturable';

    /**
     * The migration performs a DDL operation the online-DDL matrix does not classify, so
     * whether it runs online, blocks writes, or rewrites the table is unknown. Reported,
     * never a silent pass or a guessed COPY — a gap in the matrix is a gap to fill, not a
     * verdict to invent.
     */
    case UnclassifiedOnlineDdlOperation = 'unclassified_online_ddl_operation';

    /**
     * The canonical statement carries no operation key the online-DDL matrix could be asked
     * about — the shape is recognized as a schema change, but which operation it performs is
     * not derivable from it. Distinct from the unclassified case above, which means the matrix
     * has no entry for a key that WAS derived: this one never got as far as a key.
     */
    case OperationKeyUnmapped = 'operation_key_unmapped';

    /**
     * The matrix classifies the operation, but not for the server version the run reasons
     * about — every entry's version window is elsewhere. The behavior on this version is
     * genuinely unknown rather than assumed to match a neighboring version.
     */
    case OnlineDdlVersionOutOfRange = 'online_ddl_version_out_of_range';

    /**
     * The applicable matrix entry holds only while a named table or session fact is a
     * certain way (a row-version limit not yet reached, no FULLTEXT index, an ENUM append
     * that kept its storage size), and the static capture cannot see that fact. Reported
     * with the predicate named — never a silent assumption toward the cheap path.
     */
    case OnlineDdlConditionUndecidable = 'online_ddl_condition_undecidable';

    /**
     * A named table or session fact is decided AGAINST the entry's best case — the table is
     * compressed, or the row-version limit is reached — so the cheap classification does not
     * apply and the matrix has no classified alternative for the degraded case. Undetermined
     * with the predicate named, never a guess at how much worse it is.
     */
    case OnlineDdlConditionViolated = 'online_ddl_condition_violated';

    /**
     * The canonicalization could not decide whether a statement runs inside a transaction.
     *
     * The migrator's own flag is only ever yes/no, but the resolver has a third answer: an
     * explicit transaction opening inside the migrator's, an unbalanced marker, a driver
     * that declares no transaction-control markers. A lock-hygiene rule reasons about
     * exactly that fact, so an unresolved context is reported rather than read as "not in a
     * transaction" — which is the reading that makes the rule silent on the statement it was
     * least able to judge.
     */
    case TransactionContextUnknown = 'transaction_context_unknown';

    /**
     * The online-DDL matrix could not be read at all — the file is missing, unreadable, or not
     * the shape the loader expects.
     *
     * Distinct from {@see self::UnclassifiedOnlineDdlOperation}, which means the matrix WAS read
     * and has no entry for the operation. Here nothing was read, so nothing is known about any
     * operation — and a run whose data source vanished must say so rather than take the whole
     * lint down with an exception a user cannot act on.
     */
    case OnlineDdlMatrixUnavailable = 'online_ddl_matrix_unavailable';

    /**
     * The end-of-life data could not be read — the file is missing, unreadable, or not the shape
     * the loader expects, whichever of the three candidate paths it came from.
     *
     * The patch-currency check has nothing to compare a server version against without it, and
     * "nothing to compare against" is not "up to date". Loaded quietly, a missing advisory file
     * would turn every server into a clean one, which is the reading a person makes and the one
     * this package exists to prevent: the check that CANNOT run must say so.
     *
     * The finding names WHICH path was tried and why it failed, because the fix differs — a typo
     * in `sqlens.security.advisories.path`, a publish that never ran, and a truncated download are
     * three different problems that look identical from a bare "unavailable".
     */
    case AdvisoryDataUnavailable = 'advisory_data_unavailable';

    /**
     * A table's key situation could not be read off the statement that creates it.
     *
     * Two real shapes reach this. A table created FROM another one (`CREATE TABLE … LIKE`,
     * `CREATE TABLE … SELECT`) takes its keys from the source, which the statement does not
     * describe. And a table with a `UNIQUE` key but no `PRIMARY KEY` may or may not be fine:
     * InnoDB promotes the first `UNIQUE NOT NULL` index to the clustered index and the table then
     * behaves as keyed, which turns on the indexed columns' nullability rather than on the key.
     *
     * Reported rather than resolved either way. Reading it as "keyed" would be the silent green
     * this package refuses; reading it as "unkeyed" would cry wolf on a table that is fine, and a
     * linter that cries wolf on the ordinary case is one a team turns off.
     */
    case TableKeyUndetermined = 'table_key_undetermined';

    /**
     * Which unique keys a foreign key's TARGET table carries could not be read from the migration.
     *
     * The ordinary case: the target already exists, so its indexes live on the server and the lint
     * suite reads no server. It matters because MySQL 8.4 rejects a foreign key whose referenced
     * columns no unique key covers, so the question is not academic — but the ordinary answer is
     * "it references a primary key and is fine", and flagging every such statement would be crying
     * wolf on the common case. Reported instead, and settled by the audit suite, which does read
     * the live catalog.
     */
    case ForeignKeyTargetKeyUnknown = 'foreign_key_target_key_unknown';

    /**
     * The SERVER could not parse a line of its own host-based authentication file, so the fields a
     * rule would judge — the type, the address, the method — are the empty ones it left behind.
     *
     * Never a pass and never a finding about the line's content. Both would be wrong in opposite
     * directions: a `trust` on a broken line does not let anybody in, so flagging it invents a hole;
     * and the line's intended restriction is not in force, so clearing it invents a wall. The
     * finding that DOES belong is `SEC.AUTH.HBA_PARSE_ERROR`, which reports the broken line itself.
     */
    case HostAuthRuleUnparsable = 'host_auth_rule_unparsable';

    /** A one-line English explanation of why the check could not conclude. */
    public function description(): string
    {
        return match ($this) {
            self::ConnectionNotConfigured => 'The application defines no connection under the requested name.',
            self::OriginUnknown => 'The statement carries no file this run can attribute it to, so a rule that means one thing in a migration and another outside it has nothing to decide on.',
            self::ValueOriginUnknown => 'The run could not tell whether a value in this statement was written into the file or supplied at the call site, and the two are the same text by the time a rule reads them.',
            self::NotConfigured => 'The check needs a setting this project has not made, and guessing it would name the wrong thing.',
            self::TransactionPooled => 'The connection multiplexes statements across server backends, so a reading cannot be attributed to one server.',
            self::PinnedHostUnverifiable => 'The pinned host and the host the server named cannot be compared, so the identity of the audited instance is unconfirmed.',
            self::OnlineDdlMatrixUnavailable => 'The online-DDL matrix could not be read, so no operation could be classified; check the configured matrix path.',
            self::AdvisoryDataUnavailable => 'The end-of-life data could not be read, so the server version was compared against nothing; the reason names which file was tried.',
            self::DebtLedgerSchemaUnsupported => 'The debt ledger declares a schema version this build cannot act on, so it was not read at all; upgrade SQLens or migrate the file.',
            self::DebtLedgerUnreadable => 'The debt ledger file exists but is not a ledger, so what the project owes could not be read; repair it from version control or delete it deliberately.',
            self::DebtAgeUnknown => 'The debt records a first-seen date this build cannot read, or one that lies after the instant measured against, so how long it has been outstanding is unknown.',
            self::DebtObjectNotFound => 'A recorded debt names an object the catalog does not show, so whether it was settled, dropped, or simply out of this run\'s scope cannot be said.',
            self::DebtLedgerMissing => 'The debt account was expected on this machine and is not there, so whether the project has open debts is unknown — not answered with "none".',
            self::ModelNotFound => 'No Eloquent model in this application maps to that table, so whether the column is encrypted could not be read — not answered with "unprotected".',
            self::ModelNotConstructible => 'A model maps to that table and could not be constructed, so its cast list was never available; the reason names the class.',
            self::ModelCastsNotStatic => 'The model reported different casts on two constructions, so its cast list describes no fixed schema fact and none of it was used.',
            self::CustomCastOpaque => 'The column is cast through a custom castable class, which may or may not encrypt; the package will not execute it to find out.',
            self::ConflictingModelCasts => 'Two models map to that table and disagree about the column\'s cast, and neither is preferred over the other.',
            self::OpaqueBinaryColumn => 'The column stores raw bytes, which is also what server-side encryption leaves behind; whether it is protected cannot be read from the catalog or from a cast.',
            self::MigrationRoleMissing => 'The role the migrations run as does not exist on this server, so whose privileges to ask about is unanswerable — check the connection\'s username before reading any grants.',
            self::OwnershipUnreadable => 'Who owns that object could not be established — the catalog answered with no row, so either it vanished mid-check or the connecting role cannot read the row that names its owner.',
            self::TableKeyUndetermined => 'Whether the table ends up with a usable clustered key could not be read off the statement that creates it; check the table definition on the server.',
            self::ForeignKeyTargetKeyUnknown => 'The foreign key\'s target table is not created by this migration, so which unique keys it carries could not be read; confirm it has one covering exactly the referenced columns.',
            self::HostAuthRuleUnparsable => 'The server itself rejected this line of pg_hba.conf, so what it authorizes could not be read; fix the line reported by SEC.AUTH.HBA_PARSE_ERROR and audit again.',
            self::TransactionContextUnknown => 'Whether the statement runs inside a transaction could not be resolved, so a rule that reasons about the transaction boundary could not conclude.',
            self::AssumedVersionSkew => 'The assumed server version pin disagrees with the version the connected server reported, so the result reflects the pin rather than the live instance.',
            self::UnparsableMigration => 'The migration file could not be parsed, so its contents could not be inspected.',
            self::UncanonicalizableStatement => 'A captured statement could not be substituted or canonicalized into the form a rule reads.',
            self::PreScanFlagged => 'The static pre-scan flagged this migration, so it was not pretend-executed; resolve it in shadow mode.',
            self::NoActiveRules => 'A filter (the requested categories or the level) left no rules active for this run, so nothing was checked; widen the selection.',
            self::NoMigrationsRead => 'No migration was read, so the run judged nothing; --path lints the PENDING migrations of a connection, and nothing is pending once they have all run.',
            self::StatisticsUnavailable => 'The check needs the server table statistics, but no statistics reader is available in this build; it will run once the audit suite lands.',
            self::ShadowGuardBlocked => 'The production guard blocked the shadow capture, so nothing was run.',
            self::TargetIsReplica => 'The target connection is a read replica, which a database-creating mode cannot run against.',
            self::InstanceScopeUnanswerable => 'The rule speaks about this instance and its write path, and the instance that answered is not on it, so the question could not be answered here.',
            self::UuidGenerationUnknown => 'The column has no server-side default, so whether the application or the server generates its UUID could not be read; set sqlens.audit.uuid_generated_by to say which.',
            self::TextEncodingUnknown => 'The table reported no character set or collation, so what it stores text under could not be read; the storage engine may not carry one.',
            self::ReferencedObjectNotInScope => 'The question spans a second object that lies outside the audited scope, so it could not be answered; widen sqlens.catalog.schemas to include it.',
            self::UniqueNullTreatmentUnknown => 'Whether the unique index counts two NULLs as the same value could not be read, so whether the key holds across its nullable rows is unknown.',
            self::SequenceOwnershipUnclear => 'The column draws from a sequence it owns through a default that is not the shape serial produces, so whether it should become an identity column could not be answered.',
            self::IndexUsageWindowUnknown => 'How long the server has been counting index scans could not be established, so a zero scan count is not evidence that an index is unused.',
            self::ShadowSessionTimeout => 'A shadow session hit its own statement, lock, or idle-transaction timeout.',
            self::ShadowTransactionPooling => 'The shadow target sits behind a transaction pooler; configure a direct connection under capture.shadow.direct_connection.',
            self::ShadowDirectConnectionElsewhere => 'capture.shadow.direct_connection addresses a different server than the connection under examination; it must reach the same server, bypassing the pooler.',
            self::ShadowInsufficientPrivileges => 'The provisioning role lacks the privilege to create a database (PostgreSQL CREATEDB).',
            self::ShadowTemplateInUse => 'The template database has other active connections, so it cannot be cloned; disconnect them and retry.',
            self::DriftSideUnreadable => 'One object type could not be read on one side of the comparison, so that part of the schema was not compared at all; finding no drift in it would have been a claim this run cannot make.',
            self::ShadowNameCollision => 'A database with the generated shadow name already exists, so the run stopped rather than touch a database it did not create.',
            self::ShadowMysqlSchemaDumpMissing => 'The MySQL schema dump the shadow mode rebuilds from is missing or unreadable; run php artisan schema:dump.',
            self::ShadowPgsqlSchemaDumpMissing => 'The PostgreSQL schema dump the shadow template is built from is missing or unreadable; run php artisan schema:dump.',
            self::ShadowTemplateBuildFailed => 'The empty shadow template could not be built, so nothing was cloned; the half-built database was dropped.',
            self::ShadowMysqlDumpUnparseable => 'The MySQL schema dump could not be split into statements safely, so no part of it was replayed.',
            self::ShadowMysqlReplayFailed => 'A statement from the MySQL schema dump failed while it was being replayed, so the half-built shadow database was dropped.',
            self::ShadowMigrateFailed => 'An earlier migration failed during the real shadow migrate, so this one was not run.',
            self::RoundtripNoDownMethod => 'The migration defines no down(), so the roundtrip had nothing to replay and could not judge whether down() inverts up().',
            self::UpStateNotCapturable => 'A statement of the migration\'s up() was captured but not classified, so what the migration creates could not be enumerated.',
            self::DownStateNotCapturable => 'A statement of the migration\'s down() was captured but not classified, so what a rollback would destroy could not be enumerated.',
            self::ShadowTeardownFailed => 'The throwaway shadow database could not be dropped after the run and may need manual removal.',
            self::CatalogReadBudgetExceeded => 'The catalog read hit the time budget SQLens set for itself, so the reading stopped before it was complete.',
            self::CatalogReadFailed => 'The catalog read failed for a reason nothing anticipated; the database error code is reported with it.',
            self::ObjectStatisticsUnread => 'The statistics reading came back without this object, so the finding about it could not be weighed against its size. A table nobody has run ANALYZE on is the commonest cause; the verdict itself stands exactly as a run without a database would have reported it.',
            self::ConfiguredPrefixMatchedNothing => 'A table prefix is configured and no object in the audited schemas carries it, so the audit examined nothing.',
            self::MissingPrivilege => 'The connecting role lacks the privilege the check needs.',
            self::ServerUnreachable => 'The target server could not be reached.',
            self::UnknownServerVersion => 'The real server version could not be determined.',
            self::ServerVersionUnresolvable => 'No assume_server_version pin is set and the connection reported no readable version.',
            self::UnreadableServerVersionPin => 'The assume_server_version pin could not be read as a version; nothing was assumed in its place.',
            self::UnclassifiedTypeChange => 'The column type change targets a type the type-change matrix does not classify, so whether it rewrites the table is unknown.',
            self::PretendLimit => 'A result-dependent migration cannot be captured in pretend mode; shadow is needed.',
            self::UnsupportedEngine => 'The engine is not supported (MariaDB, SQLite).',
            self::ServerBelowSupportedFloor => 'The server (or the pinned version this run reasons from) is below the floor this driver\'s rules were written for, so the findings may be wrong in both directions; upgrade the server or raise the pin.',
            self::MissingExternalTool => 'An optional external tool the check relies on is not installed.',
            self::ToolRuleUnmapped => 'An external tool reported a rule this build does not know, so no category, level or severity of ours applies to it.',
            self::ToolPositionUnmappable => 'An external tool reported a position that could not be traced back to a statement of a migration.',
            self::ManagedDatabaseRestriction => 'A managed database blocks the catalog or setting the check reads.',
            self::StructurallyNotApplicable => 'The object the check targets does not exist in this schema.',
            self::UnclassifiedOnlineDdlOperation => 'The migration performs a DDL operation the online-DDL matrix does not classify, so its downtime class is unknown.',
            self::OperationKeyUnmapped => 'The statement changes the schema, but which operation it performs could not be derived from its canonical form, so the online-DDL matrix cannot be consulted.',
            self::OnlineDdlVersionOutOfRange => 'The online-DDL matrix classifies this operation, but not for the server version the run reasons about.',
            self::OnlineDdlConditionUndecidable => 'The matrix entry holds only under a table or session fact the static capture cannot see, so its classification is undetermined.',
            self::OnlineDdlConditionViolated => 'A table or session fact is decided against the matrix entry\'s best case, so its classification does not apply.',
            self::ServerExpandedDefinition => 'The server stored an expanded form of what the migration wrote, so the original text cannot be read back from the catalog.',
            self::NameSuggestsTransitionObject => 'The object\'s name matches a transition-leftover pattern, which is a heuristic and not evidence that anything is orphaned.',
        };
    }
}
