<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

/**
 * Which KIND of artifact a renderer produces — and the reason a renderer must declare one.
 *
 * One generator feeds three outputs from one snapshot: the agent-rules files a consuming project
 * keeps in its repository, the rule documentation pages, and SARIF rule metadata. They come from
 * the same catalog on purpose, because preventive guidance that drifts from the rules actually
 * enforced is worse than none.
 *
 * But they do NOT go to the same place, and that is what this enum protects. Without a family, the
 * day the documentation and SARIF renderers are registered, `sqlens:agent-rules --target=all` in a
 * consuming application would start writing documentation pages and SARIF metadata into somebody
 * else's repository — and their `--check` would go red over artifacts nobody there ordered. The
 * grouping belongs in the scaffolding rather than in the renderers that arrive later, because by
 * then the damage is a behavior change in a released command.
 */
enum ArtifactFamily: string
{
    /** The files a consuming project keeps in its own repository for its coding agents. */
    case AgentRules = 'agent_rules';

    /** The rule documentation pages — this package's own, published to the portal. */
    case Docs = 'docs';

    /** SARIF rule metadata, for a code-scanning consumer. */
    case Sarif = 'sarif';

    /**
     * The family a renderer named, or null when it named nothing this build knows.
     *
     * Null rather than a default. A renderer whose family cannot be placed is a renderer whose
     * output has no destination, and picking one for it is how a file ends up somewhere nobody
     * asked for.
     */
    public static function named(string $family): ?self
    {
        return self::tryFrom($family);
    }

    /**
     * Every family, as the names a configuration or an error message uses.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_map(static fn (self $family): string => $family->value, self::cases());
    }
}
