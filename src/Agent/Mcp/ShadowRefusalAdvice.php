<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * What an agent should DO about each way the production guard can hold a shadow run.
 *
 * ## Why the sentences differ, and why that is the whole point
 *
 * The guard has three checks and they need three different fixes: a disallowed environment is a
 * configuration decision, a production-looking connection is a target mistake, and a missing consent
 * is a setting somebody has to write down. A single "the guard refused" would make a caller try all
 * three — which is exactly the reading `GuardBlockReason` exists to prevent in the report, applied
 * here to the surface an agent acts on.
 *
 * ## Why it takes a string and not the enum
 *
 * The identifier arrives in the run header the engine wrote, as the stable English string it
 * publishes. Reaching for the enum would mean the agent layer importing the shadow capture package,
 * which its architecture test forbids for a good reason — a layer that can name the guard's internals
 * is a layer that can grow a second one.
 *
 * The completeness that costs is bought back by a test instead: it walks `GuardBlockReason::cases()`
 * and holds every one of them to a sentence of its own here. A fourth reason added upstream fails
 * that test rather than falling quietly into the generic line below.
 *
 * ## Why the generic line exists at all
 *
 * Because a version skew is real: a project can run a build whose engine names a reason this class
 * has never heard of. A crash there would turn a refusal — a correct, safe outcome — into a broken
 * tool. So an unknown check still refuses, still names itself, and simply cannot advise.
 */
final readonly class ShadowRefusalAdvice
{
    /**
     * The sentence per named check, in English.
     *
     * Machine surface, like the tool names: an agent reads it to decide what to do next. The
     * seven-locale rule covers human-facing reporter text; protocol payloads are not that, and
     * translating them would make one server answer differently depending on a setting the client
     * cannot see.
     *
     * @var array<string, string>
     */
    private const array SENTENCES = [
        'disallowed_environment' => 'the shadow mode may only run in an environment this project allows, and this is not one of '
            .'them. That check is not overridable — not by a setting, not by a parameter, not by anything this tool accepts.',
        'production_connection' => 'the target connection looks like a production instance, and a mode that creates and drops '
            .'databases never runs against one. Point the run at a development connection instead.',
        'not_confirmed' => 'nobody consented to this run. A server has no terminal, so there is no prompt to answer over the '
            .'protocol: set sqlens.agent.mcp.shadow_consent to true in the project configuration, or run '
            .'sqlens:lint --shadow from a terminal, where you can be asked.',
    ];

    /** Whether this build has advice for a named check — the seam the completeness test reads. */
    public static function knows(string $check): bool
    {
        return array_key_exists($check, self::SENTENCES);
    }

    /** The advice for a named check, or the honest admission that this build has none. */
    public static function for(string $check): string
    {
        return self::SENTENCES[$check]
            ?? 'the production guard held this run ('.$check.'), and this build has no advice for that check — it is newer than '
                .'the tool. Run sqlens:lint --shadow from a terminal to see the full message.';
    }
}
