<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Why a catalog object is NOT in the snapshot.
 *
 * A live catalog is never fully readable and never fully understood, and pretending otherwise is
 * how an audit suite becomes confidently wrong. On a managed database half the catalog is closed to
 * a non-superuser; a partial index whose predicate nobody compared cannot be reasoned about; an
 * extension's own tables are not the user's objects at all. Each of those is an ordinary, expected
 * outcome — and each has to be told apart from the others, because they need opposite responses:
 * one is a privilege to grant, one is a rule that must stay quiet, one is correct behavior.
 *
 * The backed values reach the JSON output and are **public API from 1.0**, so they stay English in
 * every locale. What gets translated is the sentence a human reads, never the identity a machine
 * matches on.
 */
enum SkipReason: string
{
    /**
     * The catalog relation itself could not be read — it does not exist on this server, or the
     * connection lost access to it mid-read.
     *
     * Deliberately NOT the bucket for a permission error: those get their own reason below, because
     * "grant this role SELECT on that view" and "this server has no such view" send a reader to
     * completely different places.
     */
    case NotReadable = 'not_readable';

    /**
     * The connecting role lacks the privilege the read needs. The ordinary case on RDS, Aurora,
     * Cloud SQL and Neon, where a non-superuser sees a fraction of the catalog — an expected
     * outcome with a concrete remedy, not a failure.
     */
    case InsufficientPrivilege = 'insufficient_privilege';

    /**
     * The object was read but not UNDERSTOOD well enough to reason about — an expression index, a
     * partial index whose predicate was not compared, a materialized view's definition.
     *
     * This is the reason the whole enum exists. The alternative to an honest skip here is a
     * redundancy heuristic that guesses, and a guess about an index is wrong in exactly the way
     * that makes a team stop believing the tool.
     */
    case NotUnderstood = 'not_understood';

    /**
     * The object was deliberately left out by configuration or by a documented default — an
     * extension's own objects, a schema outside the configured scope. Not a gap: a decision, and
     * one a reader can look up.
     */
    case ExcludedByConfig = 'excluded_by_config';

    /** The driver has no reader for this kind of object, so nothing was attempted. */
    case UnsupportedDriver = 'unsupported_driver';

    /**
     * The read stopped because it hit its own time or query budget. The reader bounds itself so an
     * audit never becomes the problem it is auditing — and a bounded read that stopped early says
     * so rather than reporting the part it managed as the whole.
     */
    case BudgetExceeded = 'budget_exceeded';

    /**
     * The database answered with an error nothing above anticipated.
     *
     * It carries a SQLSTATE or driver error code as a REQUIRED field ({@see CatalogSkip}), and that
     * requirement is the point: without it every unexpected error would drift into
     * {@see self::NotReadable}, where it would read as "this server does not have that" — and the
     * real fault would be invisible under a label that invites no investigation.
     */
    case UnexpectedError = 'unexpected_error';

    /**
     * A table prefix is configured and NOTHING in the audited schemas carries it.
     *
     * Reported rather than returned as an empty reading, because the likeliest real cause is a
     * prefix that is simply wrong — copied from another project, or read from a connection the
     * application does not use. An audit of nothing must never read like an audit of a clean schema.
     */
    case PrefixMatchedNothing = 'prefix_matched_nothing';

    /**
     * A lock the server reported in a mode this build has no neutral name for.
     *
     * The reason with the sharpest consequence in the whole enum, because of what the alternative
     * would be. A live preflight reads which locks are held so it can say whether a migration will
     * queue behind one — and a row whose mode could not be mapped is exactly the row most worth
     * seeing: an unfamiliar mode means a newer server, a provider extension, or a lock type nobody
     * here has met. Dropping it during the mapping would delete a blocking lock from the picture and
     * report calm at the one moment calm matters most.
     *
     * So the row STAYS, carrying the server's own spelling as metadata, and this reason is what
     * makes the reading visibly partial. The snapshot adds it itself rather than trusting a reader
     * to remember — a normative exclusion enforced by a constructor rather than by a sentence.
     */
    case UnmappedLockMode = 'unmapped_lock_mode';

    /**
     * The server's instrumentation is switched off, so a state view that exists and answers without
     * error nonetheless knows nothing.
     *
     * MySQL's `performance_schema` is the case this was built for, and it is the most dangerous
     * shape a gap takes here: with it off the tables are still present and still queryable, and
     * they return NO ROWS. Not an error, not a refusal — the exact answer a healthy, idle server
     * gives. A reader that trusted the emptiness would report calm for a server it cannot see at
     * all.
     *
     * Deliberately NOT `insufficient_privilege`, and the reason is the same one that keeps
     * "never collected" apart from "unknown": the remedies differ. A privilege is granted in a
     * session; instrumentation is a start-up variable, so turning it on means restarting the
     * server — a different conversation with a different person.
     */
    case InstrumentationDisabled = 'instrumentation_disabled';

    /**
     * Whether this skip means something in scope went UNREAD.
     *
     * Three classes, not two, and the middle one is the reason this method exists rather than a
     * `!== ExcludedByConfig` test at each call site:
     *
     * - **Unread** — a privilege, a budget, a driver gap, a prefix that matched nothing. The reading
     *   is not a complete statement about the schema, and silence in it cannot be trusted.
     * - **A decision** — `excluded_by_config`. Nothing went unread; a scope was chosen.
     * - **Read but not comparable** — `not_understood`. The object IS in the snapshot, complete and
     *   correct; what it cannot support is a rule REASONING about it, which is a question about the
     *   rule and not about the reading. A partial index is ordinary, and letting one turn every
     *   snapshot of an ordinary schema into a partial reading would make `isPartial()` mean nothing
     *   — the mechanism a rule uses here is the per-object `isFullyUnderstood()` predicate.
     */
    public function leavesTheReadingIncomplete(): bool
    {
        return match ($this) {
            self::ExcludedByConfig, self::NotUnderstood => false,
            default => true,
        };
    }

    /**
     * The undetermined reason a finding carries when this skip is what stopped it.
     *
     * Here rather than at the reporting end, because it is a property of the reason and not of the
     * reporter: two callers deciding it separately is how a missing GRANT and a dropped socket came
     * to be machine-indistinguishable. The audit flattened every incomplete reading onto
     * `catalog_read_failed`, and the mapping that knew better sat in a class nobody called.
     *
     * That distinction is worth the most to the people who hit it most: a managed database — RDS,
     * Cloud SQL, Neon — withholds catalog privileges by design, and `managed_database_restriction`
     * is the reason that exists to say so. Told `catalog_read_failed`, an operator goes looking for
     * a fault where there is a platform.
     *
     * `unexpected_error` keeps the catch-all deliberately: an error nobody anticipated is exactly
     * what a named reason cannot describe, and inventing a specific one would be a worse answer
     * than admitting the surprise.
     */
    public function undeterminedReason(): UndeterminedReason
    {
        return match ($this) {
            self::InsufficientPrivilege => UndeterminedReason::ManagedDatabaseRestriction,
            self::NotReadable => UndeterminedReason::StructurallyNotApplicable,
            self::BudgetExceeded => UndeterminedReason::CatalogReadBudgetExceeded,
            self::PrefixMatchedNothing => UndeterminedReason::ConfiguredPrefixMatchedNothing,
            self::UnsupportedDriver => UndeterminedReason::UnsupportedEngine,
            // Not `catalog_read_failed`: nothing failed. The server answered, and this build could
            // not name part of what it said — which is a limitation of the reader rather than of the
            // database, and points at a different fix (a mapping) than an operator would go looking
            // for if told their read had failed.
            self::UnmappedLockMode => UndeterminedReason::StructurallyNotApplicable,
            // Also not `catalog_read_failed`, and for a sharper reason than the line above: the
            // read succeeded and returned a well-formed empty set. What is missing is the server's
            // willingness to collect the data at all, which no grant and no retry changes — the
            // operator has to restart with it on, or accept that this reading cannot be made here.
            self::InstrumentationDisabled => UndeterminedReason::ManagedDatabaseRestriction,
            // A deliberate exclusion and a comprehension limit are not failures at all: the project
            // asked for the first, and the second belongs to the rule that met it. Neither leaves
            // the reading incomplete, so neither is a gap.
            self::ExcludedByConfig, self::NotUnderstood => UndeterminedReason::StructurallyNotApplicable,
            self::UnexpectedError => UndeterminedReason::CatalogReadFailed,
        };
    }

    /** The translation key for this reason's human-facing sentence. */
    public function translationKey(): string
    {
        return 'catalog.skip.'.$this->value;
    }
}
