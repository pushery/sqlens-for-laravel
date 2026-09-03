<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The findings a run makes about the state of the debt account.
 *
 * They live beside {@see DebtNotice} rather than with any one command's notices, for the reason the
 * ids do: two commands report them, and a factory per command would be two ways to phrase one
 * statement. The day the two phrasings drifted, a reader would have no way to tell which of them
 * described their database.
 *
 * ## Why the instance arrives as two strings
 *
 * A driver key and a connection name, not the audit route's target object. That type carries an
 * instance identity, a pooler reading and a pin verdict — none of which a debt notice has anything
 * to say about, and depending on it would tie the account's vocabulary to one command's view of the
 * world. Two strings are what a location actually needs.
 *
 * Nothing here reaches for a connection, a config value or a clock. A notice builder that could
 * would be a second place where the account is interpreted.
 */
final class DebtNotices
{
    /**
     * A recorded debt the catalog still shows, with how long it has been that way.
     *
     * The age is on the finding rather than left to a reader, because "open" on its own says very
     * little: the safe two-step patterns are SUPPOSED to leave something owed for a while. What
     * separates a normal deploy from a forgotten one is how long, and the severity the caller
     * passes is that number already turned into the project's own policy.
     */
    public static function stillOpen(CollectedDebt $debt, Severity $severity, string $driver, string $connection, SubjectContext $context): Finding
    {
        // The singular is spelled out rather than left to `%d days`. A debt one day old is the most
        // common one there is — every debt is, on the day it is recorded — so "open since 1 days"
        // would be the first thing most readers ever see this feature say.
        $days = $debt->age->isKnown() ? (int) $debt->age->days() : null;

        $age = $days === null
            ? 'open for an unknown length of time — its `first_seen` could not be read'
            : sprintf('open since %d %s', $days, $days === 1 ? 'day' : 'days');

        return Finding::fail(
            DebtNotice::StillOpen->id(),
            DebtNotice::MESSAGE_PREFIX,
            sprintf(
                '%s on `%s` is %s. %s',
                $debt->entry->kind,
                $debt->entry->object,
                $age,
                $debt->entry->state === DebtState::Acknowledged
                    ? 'It is carried deliberately ("'.$debt->entry->reason.'"), so its age does not escalate — the argument for caring more has already been heard and answered.'
                    : 'Finish the second half of the pattern, or record a reason for carrying it so the decision is on file rather than in somebody\'s memory.',
            ),
            Location::inCatalog($driver, $connection, $debt->entry->object, SchemaObjectType::Table),
            Category::Safety,
            DebtNotice::StillOpen->level(),
            DebtNotice::StillOpen->stability(),
            RuleDocumentationUrl::for(DebtNotice::StillOpen->id()),
            $context,
            $severity,
        )->withDebt(DebtContext::of($debt->entry, $debt->age));
    }

    /**
     * A recorded debt the catalog shows as settled.
     *
     * A PASS rather than a silence, and this is the shape that reservation exists for: the thing
     * that would normally be wrong is present in the file and cannot bite, and a reader deserves to
     * be told so rather than left to notice an absence. It is also what tells somebody the ledger
     * is behind — an account that quietly kept settled debts would overstate what a project owes.
     */
    public static function resolved(CollectedDebt $debt, string $driver, string $connection, SubjectContext $context): Finding
    {
        return Finding::pass(
            DebtNotice::Resolved->id(),
            DebtNotice::MESSAGE_PREFIX,
            sprintf(
                '%s on `%s` is recorded in the debt account and the catalog shows it settled. The entry '
                .'is left in the file: a run against a live server has a COPY of the repository, not a '
                .'working copy of it, and editing a committed file from there puts a change into '
                .'somebody\'s tree that nobody made. `sqlens:lint --debt=record` in the repository '
                .'removes it.',
                $debt->entry->kind,
                $debt->entry->object,
            ),
            Location::inCatalog($driver, $connection, $debt->entry->object, SchemaObjectType::Table),
            Category::Safety,
            DebtNotice::Resolved->level(),
            DebtNotice::Resolved->stability(),
            RuleDocumentationUrl::for(DebtNotice::Resolved->id()),
            $context,
        )->withDebt(DebtContext::of($debt->entry, $debt->age));
    }

    /** A recorded debt whose object the catalog does not show — the question left open, not answered. */
    public static function objectNotFound(CollectedDebt $debt, string $driver, string $connection, SubjectContext $context): Finding
    {
        return self::undetermined(
            DebtNotice::ObjectNotFound,
            sprintf(
                'The debt account records %s on `%s`, and the catalog does not show that object at all. '
                .'That is NOT the same as settled: a dropped table, a schema this run did not look at, '
                .'and a role without the privilege to see it all look exactly like this, and only one of '
                .'them is somebody having done the work.',
                $debt->entry->kind,
                $debt->entry->object,
            ),
            UndeterminedReason::DebtObjectNotFound,
            $driver,
            $connection,
            $context,
            $debt->entry->object,
            DebtContext::of($debt->entry, $debt->age),
        );
    }

    /**
     * A debt the catalog shows and the account has never heard of.
     *
     * A FAIL rather than an undetermined: nothing here is unknown. The catalog was read, the debt is
     * there, and the account does not mention it — which is a definite statement about the file
     * rather than a gap in the reading.
     *
     * The message says what a recording run would write and what the date would MEAN, because those
     * are different sentences here than for a migration debt. Nothing available to this package
     * knows when a legacy constraint was created; `first_seen` would be the day somebody first
     * looked, and a reader who took it for a creation date would draw the wrong conclusion from a
     * number this tool gave them.
     */
    public static function unrecorded(DebtEntry $entry, string $driver, string $connection, SubjectContext $context): Finding
    {
        return Finding::fail(
            DebtNotice::Unrecorded->id(),
            DebtNotice::MESSAGE_PREFIX,
            sprintf(
                '%s on `%s` is in the database and not in the debt account, so it has no age, no '
                .'review date and no way to be acknowledged — it will be reported identically on '
                .'every run until somebody records it. `sqlens:audit --debt=record` adds it. Its '
                .'`first_seen` will be today, and that means the day this project first LOOKED: '
                .'nothing here knows when the object was actually created, and the entry says so by '
                .'carrying `origin: catalog`.',
                $entry->kind,
                $entry->object,
            ),
            Location::inCatalog($driver, $connection, $entry->object, SchemaObjectType::Table),
            Category::Safety,
            DebtNotice::Unrecorded->level(),
            DebtNotice::Unrecorded->stability(),
            RuleDocumentationUrl::for(DebtNotice::Unrecorded->id()),
            $context,
            // Read off the enum rather than written here: the registry export reads the same
            // method, so the shipped finding and the published artifact cannot disagree about it.
            DebtNotice::Unrecorded->severity(),
        )->withDebt(DebtContext::unaged($entry));
    }

    /** The account was expected on this machine and is not there. */
    public static function ledgerMissing(string $path, string $driver, string $connection, SubjectContext $context): Finding
    {
        return self::undetermined(
            DebtNotice::LedgerMissing,
            sprintf(
                'The debt account was expected at `%s` on this machine and is not there, so whether this '
                .'project has open debts is unknown — which is a different sentence from "none". The '
                .'usual causes are the file not being deployed, or the configured path resolving against '
                .'a different working directory.',
                $path,
            ),
            UndeterminedReason::DebtLedgerMissing,
            $driver,
            $connection,
            $context,
        );
    }

    /** The account is present and this build cannot act on it — a different problem from an absent one. */
    public static function ledgerUnreadable(string $detail, UndeterminedReason $reason, string $driver, string $connection, SubjectContext $context): Finding
    {
        return self::undetermined(
            DebtNotice::LedgerUnreadable,
            sprintf(
                'The debt account is present and this build cannot act on it: %s. The run itself is '
                .'unaffected — every other rule ran and every other finding stands; only the account '
                .'could not be consulted.',
                $detail,
            ),
            $reason,
            $driver,
            $connection,
            $context,
        );
    }

    /** One undetermined notice, located on the object it is about. */
    private static function undetermined(
        DebtNotice $notice,
        string $message,
        UndeterminedReason $reason,
        string $driver,
        string $connection,
        SubjectContext $context,
        ?string $objectName = null,
        ?DebtContext $debt = null,
    ): Finding {
        $finding = Finding::undetermined(
            $notice->id(),
            DebtNotice::MESSAGE_PREFIX,
            $message,
            $reason,
            Location::inCatalog($driver, $connection, $objectName ?? $connection, SchemaObjectType::Table),
            Category::Safety,
            $notice->level(),
            $notice->stability(),
            RuleDocumentationUrl::for($notice->id()),
            $context,
        );

        // Only the notices that describe ONE recorded debt carry the account's view of it. The two
        // that do not — a missing file, an unreadable one — are statements about the ACCOUNT, and
        // giving them a `debt_kind` would invent a debt out of the fact that none could be read.
        return $debt instanceof DebtContext ? $finding->withDebt($debt) : $finding;
    }
}
