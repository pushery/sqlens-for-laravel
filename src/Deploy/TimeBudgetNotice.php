<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The run's own account of what it cost, when that cost broke the promise.
 *
 * ## Why this exists at all
 *
 * A post-deploy run hangs off the end of every deploy, and that gives it one survival condition: it
 * must not be something people wait for. A gate that visibly delays a deploy gets configured away in
 * the first sprint, and a gate nobody runs has helped nobody. So the budget is not decoration — and
 * an overrun has to travel where somebody will actually meet it, which is the report rather than a
 * line on a terminal nobody was watching.
 *
 * ## Emitted only on an overrun, and that is what keeps the output deterministic
 *
 * The measured duration is a wall-clock number: it differs on every run, on every machine, under
 * every load. Putting it in a finding that is ALWAYS present would make two runs over one unchanged
 * database produce two different documents, and every golden comparison in this repository a coin
 * toss.
 *
 * A run that keeps its budget therefore produces no finding here at all. The duration still reaches
 * a reader — `run.check_timings` gives the per-check split and `run.time_budget_ms_consumed` the sum
 * — and both are excluded from the deterministic comparison by name, because both are wall-clock.
 * This finding is the exceptional case, and an exceptional case that varies is not a determinism
 * problem: the run it describes is already not the run anyone is diffing.
 *
 * ⚠️ The second of those two was NOT emitted when this sentence was first written. It was computed,
 * put into `RunMetadata`, and dropped — the envelope never carried the metadata block, and no
 * shipped code called the projection that would have. So the comment described a key a reader could
 * not find, which is worse than describing none. The field was added to the header afterwards; the
 * sentence is true now because of that, not because it always was.
 *
 * ## It never aborts
 *
 * Nothing here stops a run. Checks the budget stopped before they started are already reported as
 * `undetermined` with that reason named ({@see CheckSequence}); this is the run's account of why
 * that happened, and it arrives after everything else has had its say. Stopping at the deadline
 * would destroy exactly the information that says what to fix.
 */
final readonly class TimeBudgetNotice
{
    public const string ID = 'DEPLOY.RUN.TIME_BUDGET_EXCEEDED';

    /**
     * What the message says about WHERE the time went.
     *
     * A method rather than a ternary inside the `sprintf`, and the reason is a property of the
     * compiler rather than a matter of taste. The no-split arm is two string literals joined by `.`,
     * and PHP folds that at COMPILE time — so the arm carries no runtime opcode, and a line-based
     * coverage driver reports it as never executed however many tests take it. Measured: with only
     * the empty-`$timings` test running, the arm it exercises came back `count=0` while the other
     * arm came back `count=1`, because that one interpolates a variable and therefore needs a real
     * CONCAT.
     *
     * Nothing about the old form was wrong. It was simply unmeasurable, and an unmeasurable line
     * under a 100% floor is a floor that cannot be met. It is not the only shape that does this:
     * a line-based driver also reports an `if` body inside a `try` as covered when it never ran,
     * because both opcodes land on one line.
     *
     * `if` with two returns, so each branch is a statement the driver can see.
     */
    private static function split(string $timings): string
    {
        if ($timings === '') {
            // Not silence. A run with no per-check split spent its time somewhere else —
            // connecting, sealing the session, rendering — and saying so is what stops a reader
            // from concluding the checks are at fault and looking there.
            return 'No per-check timings were recorded, so the time went somewhere other than the '
                .'checks: resolving the connection, sealing the session, or rendering the report.';
        }

        return 'Per check, most expensive first: '.$timings.'.';
    }

    /**
     * @param  int  $budgetMs  what the project allows
     * @param  int  $consumedMs  what the run actually took
     * @param  string  $timings  the per-check split, most expensive first, or '' when there is none
     */
    public static function exceeded(
        int $budgetMs,
        int $consumedMs,
        string $timings,
        string $driver,
        string $connection,
        SubjectContext $context,
    ): Finding {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'This post-deploy run took %d ms against a budget of %d ms. Nothing about your '
                .'database is wrong — this is what SQLens itself cost, and it is reported because a '
                .'run that visibly delays a deploy is one somebody switches off. %s Fix it where it '
                .'is slow rather than by raising the number: the split above is the only thing that '
                .'says where that is, and a budget nobody can breach is not one. If the run really '
                .'does have this much work to do, `sqlens.deploy.postdeploy.budget_ms` is the '
                .'deliberate way to say so.',
                $consumedMs,
                $budgetMs,
                self::split($timings),
            ),
            location: Location::inCatalog($driver, $connection, $connection, SchemaObjectType::Table),
            category: Category::Performance,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: $context,
            // Low, and deliberately so: the reader's attention belongs to the schema. Anything
            // higher would put the tool's own cost beside a constraint that is silently unenforced,
            // and a reader who learns to discount one learns to discount both.
            severity: Severity::Low,
        )->withDowntimeClass(
            // Online: this finding is about a READ that took too long. It holds nothing, locks
            // nothing and rewrites nothing — the complaint is entirely about the clock.
            DowntimeClass::Online,
        );
    }
}
