<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * What a run has to say about the state of the debt ACCOUNT.
 *
 * ## Why these ids name no command
 *
 * They started life as `AUDIT.DEBT.*`, because `sqlens:audit` was the first command that needed
 * them. `sqlens:postdeploy` needs the same five, and adding a `DEPLOY.DEBT.*` family beside this one
 * would have been a duplicate of exactly the kind this package refuses everywhere else: "this debt
 * is still open" is the SAME statement about the SAME object, and reporting it under two ids
 * depending on which command asked is a determinism break moved from the catalog layer to the
 * report layer.
 *
 * A consumer correlating findings across runs — a baseline, a trend report, the agent layer — would
 * see two rules where there is one, and would have to invent the equivalence itself.
 *
 * So they live here, in the namespace the account lives in, and both commands draw from them.
 */
enum DebtNotice: string implements RunNotice
{
    /**
     * A debt the committed account records and the live catalog still shows.
     *
     * The reason the account exists at all: an open end nobody finished, with its age attached so a
     * week-old one reads differently from a two-year-old one.
     */
    case StillOpen = 'DEBT.STILL_OPEN';

    /**
     * A recorded debt the catalog shows as settled.
     *
     * Reported, and removed only when somebody ASKED. `sqlens:audit` may be running on a deploy
     * server, which has a copy of the repository rather than a working copy of it, and editing a
     * committed file from there would put a change into somebody's tree that nobody made on a
     * machine where nobody could review it.
     *
     * ⚠️ That used to be written as a property of the COMMAND — "audit runs on a deploy server", so
     * it never writes. The property is the WRITE being unasked-for, not which command makes it: the
     * same run is a deploy server's on one machine and a maintainer's working copy on another, and
     * nothing available to the process tells them apart. So the default is unchanged and writes
     * nothing, and `sqlens:audit --debt=record` is the operator saying which machine this is. The
     * entry can equally go on the next `sqlens:lint --debt=record` in the repository.
     */
    case Resolved = 'DEBT.RESOLVED';

    /**
     * A debt the live catalog shows and the committed account has never heard of.
     *
     * The counterpart of {@see self::Resolved}, and the reason it did not exist for a long time:
     * the only debt producer in the package read MIGRATIONS, so a `NOT VALID` constraint that was
     * already in the database when this package arrived could not be recorded by anything. It was
     * reported on every run, identically, with no `first_seen`, no age and no way to acknowledge
     * it — the oldest debt a project carries was the only one with no date, which is exactly the
     * one a date would be worth most on.
     *
     * A finding rather than a silence, because the account is incomplete and a reader cannot tell
     * that from an account that is complete and small.
     */
    case Unrecorded = 'DEBT.UNRECORDED';

    /**
     * A recorded debt whose object the catalog does not show at all.
     *
     * Undetermined, never "settled". A dropped table, a schema outside this run's scope and a role
     * without the privilege to see it all look identical from here, and each is a different thing
     * to go and check.
     */
    case ObjectNotFound = 'DEBT.OBJECT_NOT_FOUND';

    /**
     * The account was expected on this machine and is not there.
     *
     * The one place where the recording side and the collecting side answer the same observation
     * OPPOSITELY. A repository run may read an absent file as an empty account, because nothing has
     * been recorded yet. Here it is the expected artefact: not deployed, or a path resolving
     * against a different working directory, is the likely case — and "no open debts" would be the
     * most comfortable possible wrong answer.
     */
    case LedgerMissing = 'DEBT.LEDGER_MISSING';

    /**
     * The account is present and this build cannot act on it.
     *
     * Its own case rather than a shared "unreadable", because a file that is absent and a file that
     * is corrupt send somebody to two different places.
     */
    case LedgerUnreadable = 'DEBT.LEDGER_UNREADABLE';

    /**
     * The prefix these notices report under.
     *
     * Neutral for the same reason the ids are. What `messagePrefix` fundamentally IS — a translation
     * namespace, or a statement of provenance — is a question this package has not settled; either
     * way, a finding about the account should not claim to come from a command that merely looked.
     */
    public const string MESSAGE_PREFIX = 'sqlens.debt';

    public function id(): string
    {
        return $this->value;
    }

    public function messagePrefix(): string
    {
        return self::MESSAGE_PREFIX;
    }

    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->value);
    }

    /** Each names one exact id; none of them varies over a reason the way a family does. */
    public function coversFamily(): bool
    {
        return false;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function stability(): StabilityTier
    {
        return StabilityTier::Stable;
    }

    /**
     * The severity the finding carries — and this family is the reason the slot exists.
     *
     * `DEBT.UNRECORDED` is the one run notice in the package whose finding is severity-bearing, and
     * the value is load-bearing rather than cosmetic: `DebtThresholds::escalate()` ages a debt from
     * `info` through `low` to `high`, so the severity is where that ageing starts. It used to be a
     * literal at the construction site in `DebtNotices::unrecorded()`, invisible to the registry
     * export, which stamped `severity: null` on it. Named here so the finding and the published
     * artifact read the SAME value out of one place.
     *
     * The others describe the account rather than a debt, so they carry none — stated case by case
     * instead of via `CarriesNoSeverity`, because this family can no longer make that blanket claim.
     */
    public function severity(): ?Severity
    {
        return match ($this) {
            self::Unrecorded => Severity::Info,
            default => null,
        };
    }

    /**
     * Both lanes, because the notice belongs to the ACCOUNT rather than to a command.
     *
     * @return list<Suite>
     */
    public function suites(): array
    {
        return [Suite::Audit, Suite::Deploy];
    }
}
