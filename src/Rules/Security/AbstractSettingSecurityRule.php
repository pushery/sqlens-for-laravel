<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresSecurityPosture;
use Pushery\SQLens\Contracts\JudgesTheServerItRunsOn;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;

/**
 * A security rule whose subject is a SERVER SETTING.
 *
 * The sibling of {@see AbstractSchemaObjectSecurityRule}, and the reason there are two rather than
 * one is the same single-inheritance fact that made {@see DeclaresSecurityPosture} a contract in the
 * first place. A setting rule needs the machinery in `AbstractServerSettingRule` — reading a value,
 * degrading when the server will not answer — and that class is deliberately category-neutral,
 * because the privacy suite sits on it too. So this cannot descend from the schema-object base, and
 * the two meet at the contract instead of at a parent.
 *
 * Everything else is identical: `category()` is fixed and `final` so a security setting rule cannot
 * quietly file itself elsewhere, `severity()` comes from the rule, and `limitations()` defaults to
 * empty until a rule has something honest to put there.
 */
abstract class AbstractSettingSecurityRule extends AbstractServerSettingRule implements DeclaresSecurityPosture, JudgesTheServerItRunsOn
{
    /**
     * Every rule under this base is a security rule, and none of them may say otherwise.
     */
    final public function category(): Category
    {
        return Category::Security;
    }

    /**
     * A server SETTING is the server, by definition of this base — so the whole family declares it
     * here rather than rule by rule.
     *
     * ⚠️ Deliberately not on {@see AbstractServerSettingRule}, one level up, even though every rule
     * there also reads a setting. That base is category-neutral and the privacy suite sits on it
     * too; declaring it there would hand the same withholding to rules nobody measured and nobody
     * asked about. The line is drawn where the security meaning is, which is here.
     *
     * The variable is named rather than described generically, because the point of the sentence is
     * to send a reader to the right place on the host that will actually be operated.
     */
    public function serverSubjectJudged(): string
    {
        return sprintf("this server's `%s` setting", $this->settingVariable());
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
