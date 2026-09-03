<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Pushery\SQLens\Severity\Severity;
use RuntimeException;
use Throwable;

/**
 * The rule catalog could not be resolved, and the message names which input was wrong.
 *
 * Every constructor here replaces a silent, plausible-looking answer. A snapshot is preventive
 * knowledge an agent will act on without checking, so the one thing it must never do is describe
 * a rule set that is not the one a run would apply. A driver key nobody registered, a pin that
 * does not parse, an ignore entry naming a rule that does not exist — each of those has an
 * obvious "just skip it" that would produce a catalog looking exactly as complete as a correct
 * one, and be wrong in a way nobody could see.
 *
 * So they refuse. This is the same choice the config validator makes about the same inputs, one
 * layer up: a suppression that suppresses nothing while looking set is the single most expensive
 * misconfiguration this package has, and it is expensive precisely because it is quiet.
 */
final class UnresolvableRuleCatalog extends RuntimeException
{
    /**
     * The translation key for this refusal, where one exists, and its replacements.
     *
     * Carried BESIDE the English message rather than instead of it. The two readers are different
     * people: an exception surfacing in a log or a stack trace is read by whoever is debugging, and
     * that reader wants one language they can search for. A refusal printed on somebody's terminal
     * is read by whoever ran the command, in the language they configured.
     *
     * Null on the refusals that have no key yet — an honest absence rather than a key that resolves
     * to nothing, which would print `sqlens::messages...` at somebody instead of a sentence.
     *
     * @var array<string, string>|null
     */
    public ?array $replacements = null;

    public ?string $translationKey = null;

    /**
     * No connection names a driver this package knows.
     *
     * Reached when the configured connection has no `driver` key at all — which is a broken
     * database configuration rather than an unsupported engine, and reads differently to whoever
     * has to fix it.
     */
    public static function noDriverConfigured(string $connection): self
    {
        return new self(sprintf(
            'The rule catalog needs a database driver, and the connection "%s" declares none. '
            .'Set database.connections.%s.driver, or name a connection with sqlens.connection.',
            $connection,
            $connection,
        ));
    }

    /**
     * A driver key nobody registered.
     *
     * @param  list<string>  $known
     */
    public static function unknownDriver(string $key, array $known): self
    {
        return new self(sprintf(
            'No SQLens driver is registered for "%s", so there is no rule set to describe. Registered: %s.',
            $key,
            $known === [] ? 'none' : implode(', ', $known),
        ));
    }

    /** A configured level outside the 0–9 scale. */
    public static function unknownLevel(int $level): self
    {
        return new self(sprintf(
            'sqlens.level is %d, which is outside the 0-9 scale, so the level gate cannot say which rules apply.',
            $level,
        ));
    }

    /**
     * A pin that does not parse as a version of this engine.
     *
     * Deliberately NOT a fallback to "no pin". Somebody who wrote a pin asked for a specific
     * world; answering with the unpinned catalog would hand them a different one under the name
     * they chose, which is the environment skew the pin exists to remove.
     */
    public static function unreadablePin(string $pin, string $driver): self
    {
        return new self(sprintf(
            'sqlens.assume_server_version is "%s", which is not a %s version this package can read. '
            .'Fix the pin or remove it — an unreadable pin is not the same as no pin.',
            $pin,
            $driver,
        ));
    }

    /**
     * A security floor that names no severity this package knows.
     *
     * Refused rather than read as "no floor", because that fallback is the loose direction: with
     * the severity axis off every security rule becomes advisory, and a typo would silently
     * downgrade the whole security half of the catalog.
     */
    public static function unreadableSeverityFloor(string $configured): self
    {
        return new self(sprintf(
            'sqlens.security.min_severity is "%s", which is not a severity this package knows, so no '
            .'catalog can say which rules block. Valid values: %s.',
            $configured,
            implode(', ', array_map(static fn (Severity $severity): string => $severity->value, Severity::cases())),
        ));
    }

    /**
     * One or more suppressions name rule ids that do not exist.
     *
     * @param  list<string>  $messages  one per violation, each already naming its spot
     */
    public static function unknownRuleIds(array $messages): self
    {
        $joined = implode(' ', $messages);

        $refusal = new self(
            'The rule catalog cannot be resolved while a suppression names a rule that does not exist: '
            .$joined,
        );

        // The one refusal the localization ticket names by hand, and the pattern the rest follow
        // when they are keyed: the violation text is passed through as a replacement rather than
        // translated, because it names a rule id and a config path — coordinates, not prose.
        $refusal->translationKey = 'agent_rules_unknown_ignore_rule';
        $refusal->replacements = ['violations' => $joined];

        return $refusal;
    }

    /**
     * An active rule the shipped catalog carries no metadata for.
     *
     * This is the stale-artifact direction, and it is the reason the join is checked rather than
     * trusted. `resources/data/rule-registry.json` is held byte-identical to the code by its own
     * test, so a miss here means that test was bypassed — and the failure mode without this
     * refusal is a snapshot that quietly omits a rule which really does run. An agent then never
     * hears about a check its pipeline will fail on.
     */
    public static function missingMetadata(string $id): self
    {
        return new self(sprintf(
            'Rule "%s" applies on this project but the shipped rule registry carries no metadata for it. '
            .'Regenerate it with SQLENS_WRITE_RULE_REGISTRY=1.',
            $id,
        ));
    }

    /**
     * The shipped rule metadata could not be read at all.
     *
     * Not an empty catalog, which is what a silent fallback would produce: an empty one renders
     * as "this project checks nothing", and a reader has no way to tell that from the truth.
     */
    public static function unreadableRegistry(string $path, ?Throwable $previous = null): self
    {
        return new self(
            sprintf('The shipped rule registry at %s could not be read, so no rule catalog can be resolved.', $path),
            previous: $previous,
        );
    }

    /** A registry row with no usable id — one that could never be joined to the rule it describes. */
    public static function malformedRegistryRow(string $path): self
    {
        return new self(sprintf(
            'The rule registry at %s holds an entry without a rule id; regenerate it with SQLENS_WRITE_RULE_REGISTRY=1.',
            $path,
        ));
    }

    /**
     * A rule whose documentation address is empty.
     *
     * Exported unchecked, it becomes a rule an agent is told about and cannot look up — the
     * catalog's own version of a dead link, and worse than the rule being absent, because absence
     * is at least visible.
     */
    public static function undocumentedRule(string $id): self
    {
        return new self(sprintf(
            'Rule "%s" carries no documentation URL, so it cannot be exported as preventive guidance.',
            $id,
        ));
    }
}
