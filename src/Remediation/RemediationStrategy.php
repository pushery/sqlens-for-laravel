<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

/**
 * The named safe sequences this package knows how to describe.
 *
 * The list is written ONCE and in full, deliberately. Every value is a promise in a schema that is
 * a candidate for the public API, so adding one later is a schema change with a version bump behind
 * it — and a strategy invented ad hoc when its first rule needs it is how an enum ends up with two
 * values meaning the same thing under different names.
 *
 * `none` is a value rather than a null. A rule that has looked at its finding and concluded there is
 * no safe standard sequence has said something; an absent payload says only that nobody wrote one.
 * The two are different facts and a reader acts differently on each.
 */
enum RemediationStrategy: string
{
    /** Build the index without taking the write lock the ordinary form takes. */
    case Concurrently = 'concurrently';

    /** Add the constraint unvalidated, then validate it in a second migration. */
    case NotValidThenValidate = 'not_valid_then_validate';

    /** Add the new shape, move readers and writers across, remove the old one — over three deploys. */
    case ExpandContract = 'expand_contract';

    /** Move the data in bounded batches from a job rather than in one migration statement. */
    case BatchedBackfill = 'batched_backfill';

    /** Bound how long the statement may wait and how long it may run before it is given up on. */
    case TimeoutPreamble = 'timeout_preamble';

    /** Drop across two deploy windows so a rollback in between still finds what it needs. */
    case DeployWindowDrop = 'deploy_window_drop';

    /** Reach the same end state without the operation that rewrites the whole table. */
    case RewriteAvoidance = 'rewrite_avoidance';

    /** Name the algorithm and lock level the engine would otherwise pick for you. */
    case AlgorithmLockHint = 'algorithm_lock_hint';

    /** Move the column to the new character set without a full-table conversion in place. */
    case CharsetMigration = 'charset_migration';

    /** Extend the enumeration by appending, never by rewriting its existing members. */
    case EnumAppendOnly = 'enum_append_only';

    /**
     * Give each strong lock its own migration, so each is released before the next is taken.
     *
     * Added after the original enumeration rather than with it, and the reason is worth recording
     * because this list was deliberately written in one go: it was drawn from the twelve TEMPLATE
     * tickets, and the rule this serves — a migration bundling strong locks on several tables into
     * one transaction — was not among them. Its absence was an oversight in that enumeration, not a
     * decision that no such strategy exists.
     *
     * It is set now, before any release, which is exactly when the enum's own rule says a value
     * belongs: a strategy added after 1.0 would be a schema change on a published contract. And it
     * duplicates nothing — none of the ten values above describes splitting a transaction.
     */
    case TransactionSplit = 'transaction_split';

    /**
     * A schema difference the drift comparison found, and the shape of putting it right.
     *
     * Added before the first tag, which is when this enum's own rule says a value belongs. It
     * duplicates none of the others: every strategy above describes how to make a MIGRATION safe,
     * and this one describes how to reconcile a migration state with a database that has drifted
     * from it. The steps it carries are a proposal a person decides on — SQLens writes no migration
     * file and runs no DDL.
     */
    case DriftCorrection = 'drift_correction';

    /**
     * Give the object a name of your own, short enough for the engine — the fix for an identifier
     * that goes over the limit.
     *
     * Added before the first tag, which is when this enum's own rule says a value belongs, and it
     * duplicates none of the others: every strategy above changes WHAT a migration does, and this
     * one changes only what a thing is CALLED. Nothing about the schema moves, no data is touched,
     * and there is no window to wait out — which is why folding it into an existing strategy would
     * have made a reader expect a staged sequence where a single argument is the whole remedy.
     */
    case ExplicitIdentifier = 'explicit_identifier';

    /** Looked at, and there is no safe standard sequence — a statement, not an absence. */
    case None = 'none';
}
