<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Contracts\ReadsWriteAcceptance;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Deploy\WriteAcceptance;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Whether the instance this deploy is pointed at will accept writes at all.
 *
 * ## Why this is not a louder version of the timeout findings
 *
 * Every other context check says a migration MIGHT go badly. This one says the next command will
 * fail — `migrate --force` against a standby or a read-only instance is refused outright. The gate
 * ran, said nothing, and the deploy broke two lines later on something the gate could see.
 *
 * That is a different kind of statement and it carries its own severity: not "this is risky" but
 * "this cannot work".
 *
 * ## Why the check never tries a write
 *
 * The obvious way to answer "will writes be accepted" is to attempt one and roll it back. This
 * package will not, and the reason is the promise rather than the risk: a preflight that writes has
 * written, whatever it did afterwards. A rolled-back transaction still takes locks, still burns an
 * xid, and still makes the sentence "this tool never writes to your database" false. So the state is
 * READ — from the variables the server publishes about itself.
 *
 * ## Where the engine knowledge went
 *
 * It used to be here, behind `$context->driver === 'mysql' ? … : …` with a private method on each
 * side. That is a driver decision taken in the core, and it was carried in the core-purity register
 * as a NAMED cost rather than excused — the register said in so many words that the honest remedy
 * was a driver capability. This is that capability: {@see ReadsWriteAcceptance}, one implementation
 * per engine, and nothing here that knows either engine's name.
 *
 * The two questions the answer keeps apart — a standby versus a primary somebody configured — are
 * the reason {@see WriteAcceptance} is a value object and not the `bool` the neighboring
 * `ReplicaProbe` returns.
 */
final readonly class ReadOnlyTargetCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.CONTEXT.READ_ONLY_TARGET';

    /**
     * @param  array<string, ReadsWriteAcceptance>  $capabilities  keyed by driver, supplied by the
     *                                                             composition root — the one place
     *                                                             allowed to know both engines by name
     */
    public function __construct(private array $capabilities = []) {}

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return in_array($driver, ['pgsql', 'mysql'], true);
    }

    public function run(PreflightContext $context): CheckResult
    {
        $capability = $this->capabilities[$context->driver] ?? null;

        if (! $capability instanceof ReadsWriteAcceptance) {
            // A driver this build cannot ask is `undetermined` with the reason named, never a pass.
            // The distinction matters more here than almost anywhere: a silent pass would say "this
            // instance accepts writes" about an instance nobody asked, and the deploy would then
            // fail at the migration step — the exact outcome this gate exists to prevent, arrived at
            // through the gate itself.
            return CheckResult::undetermined(
                self::ID,
                sprintf(
                    'no driver capability answers the write state for "%s", so this run cannot tell a '
                    .'writable primary from a standby. That is not a pass: an unasked question and a '
                    .'clean answer are different things, and only one of them is safe to deploy on.',
                    $context->driver,
                ),
            );
        }

        try {
            $acceptance = $capability->writeAcceptance($context->session);
        } catch (Throwable $error) {
            // Undetermined, never a pass. "The variable could not be read" and "the instance accepts
            // writes" are opposite answers, and only one of them is safe to act on.
            return CheckResult::undetermined(
                self::ID,
                'the server would not say whether it accepts writes ('.$error->getMessage().'). '
                .'Nothing follows from that: an unread setting is not a permissive one, and a deploy '
                .'sent at a standby fails whether or not this gate could see it coming.',
            );
        }

        if (! $acceptance->readOnly) {
            return CheckResult::pass(self::ID);
        }

        return CheckResult::fail(self::ID, [$this->finding($context, $acceptance)]);
    }

    private function finding(PreflightContext $context, WriteAcceptance $acceptance): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The connection "%s" reaches %s (%s). A `migrate --force` sent here is refused by the '
                .'server, so this deploy fails at the migration step rather than at this gate — which '
                .'is the same outcome with none of the warning. Point the deploy at the primary, or '
                .'clear the setting before it runs.',
                $context->connection,
                $acceptance->kind,
                $acceptance->variable,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $acceptance->variable, SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Higher than the timeout findings, and the difference is certainty rather than degree:
            // those say a migration might go badly, this says the next command will be refused.
            severity: Severity::High,
        )->withDowntimeClass(DowntimeClass::Blocking);
    }
}
