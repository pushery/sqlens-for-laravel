<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\PendingSkipReason;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\CarriesNoSeverity;
use Pushery\SQLens\Contracts\ReportsWhatTheRunObserved;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;

/**
 * The findings the RUNNER reports about itself, as a catalog rather than as literals.
 *
 * They are not rules — no rule produced them, and no rule can, because each states something
 * about the run as a whole: nothing was linted, a tool is missing, the category filter admitted
 * nothing, the version pin disagrees with the server. But a user cannot tell that from the
 * output, and should not have to: they carry an id, a message prefix and a documentation URL
 * exactly like a rule's finding does.
 *
 * That is why they are enumerated here. The five ids used to live as string literals inside
 * {@see LintRunner}, which made them invisible to anything that wants the package's full set of
 * documented findings — the registry export, and through it the "every finding has a page" check.
 * A catalog that has to be maintained by hand is a catalog that goes stale; this one cannot,
 * because the runner constructs its findings FROM it.
 *
 * ## The skip family
 *
 * {@see self::Skipped} is the one entry that is a family rather than an exact id. A concrete
 * skip reports as `LINT.SKIPPED.<reason>` ({@see PendingSkipReason}), and
 * every reason shares one page, because what a reader needs to know — why a run can end without
 * having linted anything — is the same in all of them. The export records that explicitly, so
 * the completeness check does not go looking for a page per reason.
 */
enum RunnerNotice: string implements RunNotice
{
    use CarriesNoSeverity;
    use ReportsWhatTheRunObserved;

    /** The family page for `LINT.SKIPPED.<reason>` — a run that could not lint anything. */
    case Skipped = 'LINT.SKIPPED';

    /** An external tool the run wanted is not installed, or does not run on this platform. */
    case SkippedMissingTool = 'LINT.SKIPPED.MISSING_TOOL';

    /** The category/level scope admitted no rule at all, so the run checked nothing. */
    case NoActiveRules = 'LINT.NO_ACTIVE_RULES';

    /** The assumed server version disagrees with the version the server reported. */
    case VersionSkew = 'LINT.VERSION_SKEW';

    /** The `assume_server_version` pin could not be read, and nothing was assumed in its place. */
    case VersionPinUnreadable = 'LINT.VERSION_PIN_UNREADABLE';

    /** The version this run reasons about is below the floor the driver's rules were written for. */
    case ServerBelowFloor = 'LINT.SERVER_BELOW_FLOOR';

    /**
     * A debt this run owes and the committed ledger has never heard of.
     *
     * Reported rather than recorded, because writing is a decision somebody makes with
     * `--debt=record`. Reported at all, because the alternative — noticing an open end and saying
     * nothing until asked — is the silence the account exists to end.
     */
    case DebtUnrecorded = 'LINT.DEBT.UNRECORDED';

    /**
     * A ledger entry this run no longer owes.
     *
     * It is bookkeeping, not a defect: the project settled a debt and the file has not caught up.
     * Removing it belongs to a recording run; naming it here is what tells somebody the file is
     * behind rather than letting the count quietly overstate what is owed.
     */
    case DebtStaleEntry = 'LINT.DEBT.STALE_ENTRY';

    /**
     * An ACKNOWLEDGED entry that stopped being detected.
     *
     * Deliberately not the same notice as a stale one, because the two call for opposite handling.
     * An acknowledged entry carries a written argument for being tolerated; a recording run keeps
     * it, and this notice is what puts the decision in front of a person instead of a script.
     */
    case DebtAcknowledgedGone = 'LINT.DEBT.ACKNOWLEDGED_GONE';

    /**
     * The ledger exists and this build cannot act on it.
     *
     * The one case where "no debts" would be a lie in the most comfortable direction: an unreadable
     * or future-schema file read as an empty account reports a clean project at exactly the moment
     * nobody can say whether it is one.
     */
    case DebtLedgerUnreadable = 'LINT.DEBT.LEDGER_UNREADABLE';

    /**
     * A recording run was asked for from a view that cannot support one.
     *
     * The single-file fast path sees one migration. It cannot tell an open debt from a settled one
     * — the migration that settles it is a different file — so recording from it would REMOVE
     * entries for the honest reason that this run could not see them.
     *
     * Reported as `undetermined` rather than refusing the whole run, and the difference matters
     * where `--file` actually lives: a pre-commit hook. Refusing would fail the hook and block the
     * commit over a flag combination, instead of doing the lint the hook was installed for. The
     * request is not silently downgraded either — it is named, it is undetermined, and in strict
     * mode it moves the exit code.
     */
    case DebtNotRecordable = 'LINT.DEBT.NOT_RECORDABLE';

    /**
     * An acknowledgment whose own review date has passed.
     *
     * `review_at` is the part of an acknowledgment that keeps it from becoming permanent. Somebody
     * decided to carry a debt UNTIL a moment they named; once that moment is behind us the decision
     * has expired, and reporting it is what turns "we will look at this in Q4" back into something
     * anybody looks at in Q4.
     *
     * It does not un-acknowledge the entry and it does not escalate the debt: it says the DECISION
     * is due for renewal, which is a different thing from the debt being worse.
     */
    case DebtAcknowledgmentExpired = 'LINT.DEBT.ACKNOWLEDGMENT_EXPIRED';

    /**
     * A baseline or an ignore list names a rule id that no rule of any driver carries.
     *
     * The audit half of this has existed since the check was written; the lint half did not, and
     * the difference was invisible from the outside because both produce the same thing: a run
     * that looks like it honored the file.
     */
    case InvalidConfigReference = 'LINT.INVALID_CONFIG_REFERENCE';

    /** The message prefix every runner notice reports under — the runner, not a rule. */
    public const string MESSAGE_PREFIX = 'sqlens.lint';

    public function id(): string
    {
        return $this->value;
    }

    public function messagePrefix(): string
    {
        return self::MESSAGE_PREFIX;
    }

    /**
     * The documentation page for this notice, derived like every other one
     * ({@see RuleDocumentationUrl}).
     */
    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->value);
    }

    /**
     * Whether the id names a family of concrete ids rather than one exact id.
     *
     * Only the skip page does. Stated rather than derived, so a reader of the export sees the
     * distinction without knowing the runner's internals.
     */
    public function coversFamily(): bool
    {
        return $this === self::Skipped;
    }

    /**
     * Every runner notice reports in the safety category, at the capturable level, as a stable
     * finding. Named here rather than repeated at each construction site: they describe the run,
     * so there is nothing for these axes to vary WITH.
     */
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
     * The suites a runner notice can appear in. The lint runner is the only thing that emits
     * them, so the answer is the lint suite alone — stated rather than left implicit, because
     * the registry export lists notices next to rules and an empty suite list there would read
     * as "belongs nowhere" instead of "belongs to the runner".
     *
     * @return list<Suite>
     */
    public function suites(): array
    {
        return [Suite::Lint];
    }
}
