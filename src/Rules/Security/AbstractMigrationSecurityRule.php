<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresSecurityPosture;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Rules\ReadsMigrationStatements;

/**
 * A security rule whose subject is a MIGRATION — the canonical statement, never the grammar output.
 *
 * The third member of the family {@see DeclaresSecurityPosture} exists for, and the one that had no
 * user until now: of fifty-nine files under `src/Rules/Security`, not one judged a migration. The
 * suite read the live catalog only. So a `GRANT … TO PUBLIC` written into a migration was invisible
 * until it had already been applied and a later audit found it on the server — which is exactly one
 * deploy too late for the thing this package is about.
 *
 * ## Why it does not extend the safety base
 *
 * `AbstractSafetyRule` has the machinery and states in its own docblock why it cannot lend it:
 * *"Every rule in this family is a safety rule; that is what the family means."* Its `category()` is
 * `final`, deliberately — sixty-five rules depend on that answer being unavailable to override.
 *
 * Subject family and category family are different axes, and PHP gives a class one parent. So the
 * machinery moved into {@see ReadsMigrationStatements}, both bases use it, and each keeps its own
 * `final category()`. Nothing about the safety family changed; its whole suite proves that.
 *
 * ## What a rule under this base must answer
 *
 * `severity()`, through the contract — `security.min_severity` is the only dial a project has over
 * this suite, and a rule that answers null cannot be compared against it. The arch test holds it,
 * because the type system cannot: the inherited default is concrete and returns null, correctly, for
 * the safety rules that share the trait.
 *
 * ## Path binding is the rule's own job, not the base's
 *
 * The asymmetry is deliberate and belongs to the RULE, not to this base. A password literal is
 * Critical inside `database/migrations` and noise inside a seeder, so a secrets rule binds itself to
 * the migration paths. A `GRANT … TO PUBLIC` is a finding wherever it is written, so the grant rules
 * do not. Filtering here would impose one of those answers on both, silently, and the next reader
 * would take the narrowing for a rule of the family rather than a choice one rule made.
 */
abstract class AbstractMigrationSecurityRule implements DeclaresSecurityPosture, Rule
{
    use ReadsMigrationStatements;

    /**
     * Every rule under this base is a security rule, and none of them may say otherwise.
     *
     * `final` for the same reason it is final on the safety base: a security rule filed under
     * another category leaves the suite silently and keeps passing every test it has.
     */
    final public function category(): Category
    {
        return Category::Security;
    }

    /**
     * What this rule cannot see — a real sentence per gap, never a formula.
     *
     * ABSTRACT, and it became abstract only once every rule had an answer. The default used to be an
     * empty array, and its own docblock explained why: making it abstract while 43 of 50 rules were
     * silent would have forced them all to answer in the same change that moved them, "which is how
     * a mechanical migration turns into 43 pieces of invented prose".
     *
     * The content came first, family by family. With all 50 answering, the default stopped being a
     * default and became dead code — measured, as an uncovered line in the coverage floor. Removing
     * it turns the contract from something a guard enforces into something the type system does.
     *
     * @return list<string>
     */
    abstract public function limitations(): array;
}
