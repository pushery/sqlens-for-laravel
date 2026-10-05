<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Contracts\DeclaresSecurityPosture;

/**
 * An engine rule that names what it does not answer.
 *
 * The security rules carry this slot through their public contract, {@see DeclaresSecurityPosture}.
 * A few engine rules have limits worth stating as well, and this interface gives them the slot
 * without widening the public extension surface. The rule registry reads both, so each sentence
 * reaches the shipped catalog and every answer `explain_rule` gives about the rule.
 */
interface DeclaresLimitations
{
    /**
     * What this rule deliberately does not answer, one sentence each.
     *
     * Empty means nothing the rule claims to cover escapes it, never that nobody looked.
     *
     * @return list<string>
     */
    public function limitations(): array;
}
