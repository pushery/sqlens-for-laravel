<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Privacy;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Security\PatchEolRule;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\JudgesProductionOnly;
use Pushery\SQLens\Security\Privacy\ProductionVerdict;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A server setting whose value is only a privacy problem on a production instance.
 *
 * ## Why the environment is a PRECONDITION and not part of the judgment
 *
 * Full statement logging writes personal data in clear text into files that rarely enjoy the
 * database's protection. On a developer's laptop the same setting is how people debug. The value is
 * identical; what differs is the machine it is set on, which is not a property of the value at all.
 *
 * Folding that into {@see AbstractServerSettingRule::violation()} would mean each rule re-deciding
 * the same question and, worse, expressing "I could not place this server" as "the value is fine" —
 * because a violation hook has only those two answers. So the question is asked once, here, through
 * the hook that may answer with any verdict.
 *
 * ## The third answer is the point
 *
 * {@see ProductionVerdict} is three-valued because guessing "not production" is the expensive
 * mistake: a rule that read "cannot tell" as "not production" would report a `pass` about a server
 * it never placed, and a pass asserts that the check ran and found the situation acceptable. An
 * unplaceable environment is therefore `undetermined` with a named reason — the same three-valued
 * rule this package applies to every other check that cannot run.
 *
 * ## Where the environment comes from
 *
 * Injected at registration, defaulted to null, exactly like {@see PatchEolRule}'s
 * advisory repository. Not the `withMatrix()` clone shape: that exists because a settings matrix is
 * built from a FILE through a named constructor and a default expression cannot read one. A
 * `RunEnvironment` has no such problem — it takes two services the container already holds.
 *
 * Without one, every judgment is `undetermined`. That is the honest answer rather than a
 * convenience: a rule that cannot tell which environment it is looking at has not established the
 * premise its finding rests on.
 */
abstract class AbstractPrivacySettingRule extends AbstractServerSettingRule
{
    use JudgesProductionOnly;

    public function __construct(
        string $projectRoot,
        private readonly ?RunEnvironment $environment = null,
    ) {
        parent::__construct($projectRoot);
    }

    /**
     * Every rule under this base is a privacy rule, and none of them may say otherwise.
     *
     * `final` for the reason the three security bases carry it: privacy is a severity-GATED
     * category, so a rule that filed itself elsewhere would stop being weighed against
     * `security.min_severity` and would leave its suite without erroring, without a warning, and
     * with every one of its own tests still green.
     *
     * It was not final until a guard stopped naming the bases it checked and started deriving them
     * from the rules being served. Two security bases were listed by hand; this one was not a
     * security base, so nothing looked at it at all.
     */
    final public function category(): Category
    {
        return Category::Privacy;
    }

    /**
     * Level 0, and it is not a strictness statement.
     *
     * Privacy and security rules are gated on their own severity axis rather than on the level, so
     * the level here only has to be low enough never to hide one. Putting it anywhere else would
     * make a run at a lower level silently drop a privacy finding — a shorter report that does not
     * say it is shorter.
     */
    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * Yes — a privacy rule judges the value from the environment it was handed, not from the matrix.
     *
     * The matrix abstains on these settings for a reason that is right and that this family answers:
     * the value alone cannot say whether it is a problem. Having established the environment in
     * {@see self::precondition()}, the rule has what the matrix could not have.
     */
    #[Override]
    protected function bringsOwnExpectation(): bool
    {
        return true;
    }

    /** What this rule would report if the environment were production — for the pass sentence. */
    abstract protected function privacyConcern(): string;

    /**
     * The concern, under the shared trait's name.
     *
     * Kept as a thin bridge rather than renaming `privacyConcern()` across the family: the shared
     * precondition serves a SECURITY rule too now, so its hook cannot be named for one category —
     * and the privacy rules' own vocabulary is worth more than the one line this costs.
     */
    #[Override]
    protected function environmentConcern(): string
    {
        return $this->privacyConcern();
    }

    protected function precondition(SchemaObject $object): ?RuleVerdict
    {
        return $this->productionPrecondition($object, $this->environment);
    }
}
