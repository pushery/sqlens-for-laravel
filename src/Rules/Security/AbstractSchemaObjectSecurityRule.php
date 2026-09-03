<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresSecurityPosture;
use Pushery\SQLens\Rules\AbstractCatalogRule;

/**
 * A security rule whose subject is a SCHEMA OBJECT — a role, a grant, a setting, a routine.
 *
 * The thin piece between `AbstractCatalogRule`, which already knows how to be asked about a schema
 * object, and the security suite, which adds an axis of its own. It introduces no machinery: every
 * rule that extends this was already a catalog rule and stays one.
 *
 * ## What it removes
 *
 * `category()` was written out in every security rule and every security topic base — the same three
 * lines, once per file. Repetition is the smaller half of the problem; the larger half is that a
 * repeated answer can be given WRONGLY in one place, and a security rule filed under another
 * category is not a loud failure. It leaves the security suite, quietly, while still passing every
 * test it has. Declared `final` here, that stops being possible rather than merely unlikely.
 *
 * ## What it requires
 *
 * `severity()`, through {@see DeclaresSecurityPosture}. A security rule without one cannot be gated
 * by `security.min_severity`, and an ungated security rule is either always on or always off — both
 * of which take the choice away from the project it is supposed to serve.
 *
 * It is NOT re-declared here, and the obvious version of this class gets that wrong twice. Narrowing
 * the contract to a non-nullable `Severity` makes the `?Severity` every rule inherits from
 * `RuleMetadataDefaults` incompatible; re-declaring it `abstract` is refused outright, because PHP
 * will not make an inherited CONCRETE method abstract — and that default is concrete, returning null,
 * which is the right answer for the safety rules sharing the trait. The type system therefore cannot
 * state "a security rule has a real severity" at all, so an arch test does: it walks every
 * implementation of the contract and fails on a null. That catches the security rule written next
 * month that never mentions severity and silently inherits the safety default.
 *
 * `limitations()` has a default, and the default is deliberately empty rather than abstract. Making
 * it abstract would force all 28 existing rules to answer it in the same change that moves them,
 * which is how a mechanical migration turns into 28 pieces of invented prose. Empty means "nothing
 * this rule claims to cover escapes it", and naming the real ones is its own piece of work.
 *
 * ## The subject kinds this does NOT cover
 *
 * {@see AbstractMigrationSecurityRule} now sits beside this one and is served, which is what that
 * class was waiting for — a base with no real user is scaffolding claiming to be a seam, so it
 * arrived WITH its rules rather than before them. It implements the same
 * {@see DeclaresSecurityPosture} from a different parent, which is the whole reason that contract
 * is a contract.
 *
 * `AbstractRawSqlSecurityRule` still does not exist, and the reason has changed from "nothing would
 * use it" into something stronger: the raw-SQL security surface EXISTS and is not shaped like this.
 * The three `SEC.INJ.*` rules read PHP source, so they are PHPStan rules registered through
 * `extension.neon` and composed by `AnalyseRuleCatalog` — the right
 * home for a check whose subject is a call site rather than a database. A base on this contract over
 * the same surface would be a second seam across one subject, and the two would answer the same
 * question differently the first time either moved.
 *
 * ⚠️ This paragraph carried a hand-counted "of 57 rule files, none judges a migration" and both
 * halves went stale: the directory holds seventy, and fourteen served rules judge migrations. A
 * reader trusting it would either rebuild a class that already exists or conclude the migration
 * surface is uncovered. The claim that replaced it is checkable rather than counted —
 * `SecurityPostureContractTest` derives the bases from the rules being served, so a base named here
 * and a base in use cannot drift apart without something going red.
 */
abstract class AbstractSchemaObjectSecurityRule extends AbstractCatalogRule implements DeclaresSecurityPosture
{
    /**
     * Every rule under this base is a security rule, and none of them may say otherwise.
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
