<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Privacy;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Security\SecurityRuleSet;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A column whose NAME says personal data and whose model says plain text.
 *
 * The core of the privacy pack, and the only rule in it that reads the schema rather than a server
 * setting. It joins two readings that are useless apart: the dictionary knows that `iban` and
 * `geburtsdatum` name the kind of thing a leak is expensive for, and the application's Eloquent
 * casts know whether the value is encrypted before it reaches the row.
 *
 * ## Why this rule can be quiet in two different ways
 *
 * Its severity is not fixed, which is unusual here and deliberate. The dictionary sorts its terms
 * into a STRONG and a WEAK signal — `iban` is an IBAN essentially always, while `religion` is also
 * an ordinary column in a CMS — and the artifact records the difference precisely so the finding can
 * be quieter where the guess is weaker.
 *
 * The alternative was two rule IDs for one concern, and that cost is paid by consumers rather than
 * here: an id appears in committed baselines, in `#[SqlensIgnore]` annotations and in a
 * documentation URL, so a split would make every project suppress the same thing twice. The verdict
 * carries the severity instead.
 *
 * Both values sit BELOW the security gate's `high` default. That is the guardrail this rule ships
 * with: a name heuristic that broke somebody's pipeline would be switched off within a week, and it
 * would take its true positives with it.
 *
 * ## It never reads a value, and the finding says so
 *
 * `iban` may hold an IBAN or a label for one, and nothing in a catalog distinguishes them. The
 * honesty limit is written into the finding text rather than left in documentation a reader may not
 * have open, together with the two things they can do about it.
 *
 * ## A column with no model is UNDETERMINED, never fine
 *
 * The common case in a real application is not "encrypted" or "plain" — it is a table no model maps
 * to, a model that will not construct, or a custom cast this package may not execute. Each is a
 * named `undetermined`, because a run that stayed silent about them would be indistinguishable from
 * a run over an application that encrypts everything.
 */
final class UnencryptedColumnRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Whether the missing-wiring answer has already been given in this run.
     *
     * ONE finding, not one per column. A reading of a modest schema carries thousands of columns, and
     * a rule that answered `undetermined` for every one of them would bury every other finding in the
     * report under a single fact repeated — which is the same failure as silence, only louder.
     *
     * Instance state is the right scope: a rule is constructed per driver resolution, so "this run"
     * and "this instance" are the same thing.
     */
    private bool $announcedMissingWiring = false;

    /**
     * The evaluator is injectable so a test can hand in a dictionary and a model set built for the
     * case under test, and lazily defaulted so the ordinary registration keeps the one-argument
     * shape every other rule in {@see SecurityRuleSet} uses.
     *
     * Lazy for a second, measured reason: building it DISCOVERS MODELS off the filesystem and reads
     * the dictionary artifact. Every rule is constructed on every run, and the privacy pack is off
     * by default — paying for a directory walk on construction would charge every run for a rule
     * that is usually not even admitted.
     */
    public function __construct(string $projectRoot, private readonly ?UnencryptedColumnEvaluator $evaluator = null)
    {
        parent::__construct($projectRoot);
    }

    public function id(): string
    {
        return 'SEC.PII.UNENCRYPTED_COLUMN';
    }

    /**
     * Capturable, like the rest of the privacy pack: nothing here is about a migration's blast
     * radius, so the level axis has nothing to say and the severity axis carries the weight.
     */
    public function level(): Level
    {
        return Level::Capturable;
    }

    public function category(): Category
    {
        return Category::Privacy;
    }

    /**
     * The floor, and the value a verdict that names none falls back to.
     *
     * `Low` rather than `Info` because it is the value the STRONG signal carries, and a verdict that
     * lost its severity should land on the louder of the two — a heuristic finding that arrives
     * quieter than intended is one nobody reads.
     */
    #[Override]
    public function severity(): Severity
    {
        return Severity::Low;
    }

    /**
     * `online`: this rule reports on a column that already exists and proposes no DDL at all. The
     * remedy is a cast on a model, which the database never learns about.
     */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /**
     * `preview`, and it stays there until the heuristic has been run against real schemas.
     *
     * The package's default is `stable`, which is right for a rule that reads a server variable and
     * compares it to a documented value. This one GUESSES from a name, and the shipped dictionary
     * has never met anybody's column names. Preview says exactly that: it is opt-in twice over — the
     * pack has to be switched on AND preview rules admitted — so nobody meets it by upgrading.
     */
    #[Override]
    public function stability(): StabilityTier
    {
        return StabilityTier::Preview;
    }

    /** @return non-empty-list<Suite> */
    public function suites(): array
    {
        return [Suite::Security];
    }

    /**
     * Columns only. A rule handed a table or an index would find no name to match and no model to
     * ask, and narrowing here is what keeps that from being re-derived per subject.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Column];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        // Absent, this rule says UNDETERMINED rather than nothing — the same shape
        // {@see AbstractPrivacySettingRule} uses for a missing environment, and for the same
        // reason. Silence here would be indistinguishable from an application that encrypts
        // everything, which is the one reading that must never be reachable by accident.
        // BEFORE the wiring check, and the order is load-bearing. A rule that answered about a
        // table or an index while declaring only columns would be reported as never evaluated on a
        // reading that handed it exactly its subject — the architecture arm that measures
        // declaration against BEHAVIOR catches precisely this, and caught it here.
        if ($object->type !== SchemaObjectType::Column) {
            return [];
        }

        if (! $this->evaluator instanceof UnencryptedColumnEvaluator) {
            if ($this->announcedMissingWiring) {
                return [];
            }

            $this->announcedMissingWiring = true;

            return [RuleVerdict::undetermined(
                'the privacy pack\'s column reading was not wired into this run, so NO column was '
                .'checked for an encrypted cast — this is not a clean result. Reported once for the '
                .'run rather than once per column: the fact is about the run, and repeating it for '
                .'every column would bury every other finding in the report.',
                UndeterminedReason::ModelNotFound,
            )];
        }

        $verdict = $this->evaluator->judge($object);

        return $verdict instanceof RuleVerdict ? [$verdict] : [];
    }
}
