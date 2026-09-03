<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Pedantic;

/**
 * What a project asked to be documented, and which objects it does not want judged on.
 *
 * ## Built once, outside the rules, for the reason every other policy here is
 *
 * There are TWO comment rules, one per engine, sharing one judgment. A rule that read the
 * configuration itself would have a verdict its own tests cannot see, and the two would eventually
 * disagree about what a malformed value means. So this is constructed where the rule set is, from
 * the raw `sqlens.audit.documentation` array, and handed down.
 *
 * It also keeps `config()` out of the shipped rules. This package declares focused `illuminate/*`
 * components rather than `laravel/framework`, and the helper belongs to the framework — a guard
 * reads the source for exactly that.
 *
 * ## Both switches default OFF, and that is the design rather than caution
 *
 * Level 9 already keeps these rules out of an ordinary run. It is not enough: a project that raised
 * its level to see the pedantic band asked for opinionated findings, not to be told in the same
 * breath that every table it owns is undocumented. The two switches are separate because they are
 * different amounts of work — documenting tables is something a team can finish, and folding the
 * two together would make the cheaper half unreachable.
 */
final readonly class DocumentationPolicy
{
    /**
     * @param  list<string>  $exempt  bare table names, matched whole
     */
    private function __construct(
        public bool $requireTableComments,
        public bool $requireColumnComments,
        public array $exempt,
    ) {}

    /** What ships: both switches off, and the framework tables exempt. */
    public static function shipped(): self
    {
        return new self(false, false, MissingComment::FRAMEWORK_TABLES);
    }

    /**
     * The policy a project configured, falling back to the shipped one for anything unusable.
     *
     * A non-boolean switch is read as OFF rather than as ON: the failure direction matters, and a
     * typo that turned the most opinionated rule in the catalog ON is the wrong way to be wrong.
     *
     * @param  mixed  $documentation  the raw `sqlens.audit.documentation` value
     */
    public static function fromConfig(mixed $documentation): self
    {
        if (! is_array($documentation)) {
            return self::shipped();
        }

        $exempt = $documentation['exempt'] ?? null;

        return new self(
            ($documentation['require_table_comments'] ?? null) === true,
            ($documentation['require_column_comments'] ?? null) === true,
            // A configured list REPLACES the shipped one rather than adding to it, so a team naming
            // its own set is not silently still carrying ours. Anything that is not a list falls
            // back to the framework names — including null, which is the shipped default and means
            // exactly that.
            is_array($exempt)
                ? array_values(array_filter($exempt, static fn (mixed $entry): bool => is_string($entry) && $entry !== ''))
                : MissingComment::FRAMEWORK_TABLES,
        );
    }
}
