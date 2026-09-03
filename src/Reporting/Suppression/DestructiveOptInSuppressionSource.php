<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Attributes\SqlensAllowDestructive;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Subjects\MigrationSql;
use ReflectionClass;
use Throwable;

/**
 * The destructive opt-in, expressed as a suppression the reporter shows rather than
 * a silent skip inside the rules.
 *
 * A destructive migration operation — DROP TABLE, DROP COLUMN, TRUNCATE, a mass
 * UPDATE/DELETE with no WHERE, or a drop without a deploy window — is a real finding
 * the rules always produce. Consent does not un-produce it; it moves it to the
 * suppressed list with a NAMED reason, so a run still shows that this migration
 * destroys data. That is the whole point of the opt-in living here and not in the
 * rule: "the migration opted in" and "the rule never looked" are different facts,
 * and only one of them is true, so only one may be shown.
 *
 * Consent comes from two sources, most specific first:
 *
 *  - **The migration's own `#[SqlensAllowDestructive]`** — an in-code attribute with a
 *    mandatory reason, applying to THIS migration only. Its reason is the one shown,
 *    because a person wrote it about this exact operation. Read by reflection off the
 *    class the capture path already loaded (`class_exists` with autoload OFF), never by
 *    parsing the file, and fail-safe toward flagging: a malformed attribute (one missing
 *    its reason) is treated as NO consent, so the destructive finding stays visible.
 *  - **The project-wide `sqlens.allow_destructive` config switch** — for a project that
 *    has decided, as a whole, that destructive migrations are expected. It suppresses
 *    with a fixed reason naming the switch, so the report says WHERE the consent came
 *    from.
 *
 * It consents ONLY to the destructive family below — a rule id it does not recognize is
 * never suppressed here, so this source can never hide an unrelated finding. Applying
 * the suppression (recording the source and reason on the hidden finding) is done here
 * because, unlike the ignore/annotation sources, the reason has two shapes and this is
 * the one place that knows which applies.
 */
final readonly class DestructiveOptInSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'destructive_opt_in';

    /**
     * The rule ids the destructive opt-in consents to — the level-1 data-loss family
     * (schema drops, truncate, a WHERE-less mass write) and the level-4 deploy-window
     * rule that reviews the same drop. A finding outside this set is never this source's
     * to suppress.
     *
     * @var list<string>
     */
    private const array FAMILY = [
        'PG.L1.DROP_TABLE',
        'PG.L1.DROP_COLUMN',
        'PG.L1.TRUNCATE',
        'PG.L4.DROP_WITHOUT_DEPLOY_WINDOW',
        'GEN.L1.DML_WITHOUT_WHERE',
    ];

    /** @param  bool  $allowedProjectWide  the resolved `sqlens.allow_destructive` switch */
    public function __construct(private bool $allowedProjectWide = false) {}

    /**
     * The consent covering this destructive finding, or null. Null means either the
     * finding is not a destructive-family one (this source stays out of it) or nothing
     * consented to it (it stays visible). The migration's own reason wins over the
     * project-wide one — it is the more specific statement about this operation.
     */
    public function consentFor(Finding $finding, ?MigrationSql $subject): ?Suppression
    {
        if (! in_array($finding->ruleId, self::FAMILY, true)) {
            return null;
        }

        if ($subject instanceof MigrationSql) {
            $reason = $this->annotationReason($subject->annotationClass);

            if ($reason !== null) {
                return new Suppression(
                    source: self::SOURCE,
                    reason: 'the migration opted in with #[SqlensAllowDestructive]: '.$reason,
                );
            }
        }

        if ($this->allowedProjectWide) {
            return new Suppression(
                source: self::SOURCE,
                reason: 'allowed project-wide by sqlens.allow_destructive',
            );
        }

        return null;
    }

    /**
     * The reason on the migration's `#[SqlensAllowDestructive]`, or null when the class
     * carries none, was never loaded, or carries a malformed one (missing its mandatory
     * reason) — the fail-safe direction, so a broken opt-in surfaces the finding rather
     * than swallowing it.
     */
    private function annotationReason(?string $migrationClass): ?string
    {
        if ($migrationClass === null || ! class_exists($migrationClass, autoload: false)) {
            return null;
        }

        foreach (new ReflectionClass($migrationClass)->getAttributes(SqlensAllowDestructive::class) as $attribute) {
            try {
                // newInstance() enforces the mandatory reason: an opt-in without one
                // throws here and is not honored, so the destruction stays flagged.
                return $attribute->newInstance()->reason;
            } catch (Throwable) {
                return null;
            }
        }

        return null;
    }
}
