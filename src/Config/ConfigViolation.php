<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * One configuration violation: the dotted path of the offending key, what the
 * schema expects there, and what was actually found. Violations are collected,
 * never thrown one at a time — a user fixing their config deserves the whole
 * list in one run, not a fix-rerun loop that surfaces them one by one.
 *
 * ## The messages are English, and that is a decision rather than a stage
 *
 * They are part of the console output, not the public wire format — the JSON envelope carries the
 * structured fields, so the phrasing could in principle be reworded at the reporter without breaking
 * a machine consumer.
 *
 * It will not be. This package ships ONE locale, deliberately: everything it emits goes to a
 * terminal, a CI annotation, a SARIF file or an agent artifact, and none of those is a user
 * interface. `tests/Unit/LocaleParityTest.php` is inverted for exactly that reason and goes red if a
 * second locale directory appears, so a translation path built here would take the guard with it.
 *
 * The case is stronger for a CONFIG message than anywhere else. It names a dotted key that is
 * English (`sqlens.security.min_severity`), quotes a value from a file whose comments are English,
 * and is read by the person editing that file. A translated sentence wrapped around an untranslated
 * key helps less than it costs.
 *
 * This paragraph replaced one that said the phrasing "can be translated at the reporter". That
 * sentence was written as a note about what the design allowed, and it read as a plan — enough for a
 * later ticket to file the missing translations as a gap. Saying what will NOT be built is part of
 * saying what was.
 */
final readonly class ConfigViolation
{
    private function __construct(
        public ConfigViolationKind $kind,
        public string $path,
        public string $expected,
        public string $found,
    ) {}

    /** @param  list<string>  $knownKeys */
    public static function unknownKey(string $path, array $knownKeys): self
    {
        return new self(
            kind: ConfigViolationKind::UnknownKey,
            path: $path,
            expected: 'one of: '.implode(', ', $knownKeys),
            found: 'an unrecognized key',
        );
    }

    /**
     * The Laravel dot-notation trap: a literal `'security.min_severity' => …`
     * top-level key LOOKS like the nested path `config('sqlens.security.min_severity')`
     * reads, but the repository resolves dots by traversing nested arrays, so the
     * literal key is silently never read. That near-miss deserves its own kind with
     * the exact rewrite, not a generic "unknown key".
     */
    public static function dottedLiteralKey(string $relativeKey): self
    {
        $segments = explode('.', $relativeKey, 2);

        return new self(
            kind: ConfigViolationKind::DottedLiteralKey,
            path: 'sqlens.'.$relativeKey,
            expected: sprintf("a nested section: '%s' => ['%s' => …]", $segments[0], $segments[1]),
            found: sprintf("the literal key '%s'", $relativeKey),
        );
    }

    /**
     * The id names a real rule that does not run in this suite.
     *
     * Separated from {@see unknownRuleId()} on purpose: they send a reader to different places. A
     * lint rule id written into the audit ignore block is a mistaken assumption about where a rule
     * lives, not a spelling mistake — and telling somebody their correctly spelled id is unknown
     * sends them hunting a typo that is not there.
     */
    public static function ruleNotInSuite(string $where, string $ruleId, string $suite, string $answersIn): self
    {
        return new self(
            kind: ConfigViolationKind::RuleNotInSuite,
            path: $where,
            expected: sprintf('a rule that answers in the %s suite', $suite),
            found: sprintf('"%s", which is a real rule but answers in %s', $ruleId, $answersIn),
        );
    }

    /**
     * A suppression names a rule id no rule answers to. Its own kind, because the
     * consequence is specific and severe: the rule keeps firing while the user
     * believes it is off, so they read past its findings indefinitely.
     */
    public static function unknownRuleId(string $where, string $ruleId, ?string $suggestion): self
    {
        return new self(
            kind: ConfigViolationKind::UnknownRuleId,
            path: $where,
            // The suggestion is offered, never applied — rule ids are public API,
            // so nothing here resolves a near-miss on the user's behalf.
            expected: $suggestion === null
                ? 'a registered rule id (no close match found)'
                : sprintf('a registered rule id — did you mean "%s"?', $suggestion),
            found: sprintf('the unregistered rule id "%s"', $ruleId),
        );
    }

    public static function missingKey(string $path, string $expected): self
    {
        return new self(
            kind: ConfigViolationKind::MissingKey,
            path: $path,
            expected: $expected,
            found: 'nothing (the key is absent)',
        );
    }

    /**
     * An absent SCHEMA key: the shipped default applies and the run continues.
     *
     * Same shape as {@see missingKey()} on purpose — a reader gets the same path and the same
     * expectation text, so the two read as one family and the only difference is the consequence.
     */
    public static function defaultedKey(string $path, string $expected): self
    {
        return new self(
            kind: ConfigViolationKind::DefaultedKey,
            path: $path,
            expected: $expected,
            found: 'nothing (the key is absent)',
        );
    }

    public static function wrongType(string $path, string $expected, mixed $found): self
    {
        return new self(
            kind: ConfigViolationKind::WrongType,
            path: $path,
            expected: $expected,
            found: self::describe($found),
        );
    }

    public static function outOfRange(string $path, string $expected, mixed $found): self
    {
        return new self(
            kind: ConfigViolationKind::OutOfRange,
            path: $path,
            expected: $expected,
            found: self::describe($found),
        );
    }

    /**
     * The same violation, reported at a different path. A profile reuses the base
     * config's leaf specs wholesale — one source for what a value may be — but the
     * message has to name the key the user actually wrote: pointing them at
     * `sqlens.level` for a value they set under `sqlens.profiles.ci.level` sends
     * them to the wrong line of their config.
     */
    public function at(string $path): self
    {
        return new self($this->kind, $path, $this->expected, $this->found);
    }

    /** The full human-readable line: path, kind, expected value, found value. */
    public function message(): string
    {
        return sprintf('%s: %s — expected %s, found %s.', $this->path, $this->kind->phrase(), $this->expected, $this->found);
    }

    /**
     * Render a found value with its type spelled out — `string "3"` and
     * `integer 3` must stay distinguishable, because a quoted level in an env
     * var is exactly the kind of mistake this validator exists to surface.
     */
    private static function describe(mixed $value): string
    {
        return match (true) {
            $value === null => 'null',
            is_bool($value) => 'boolean '.($value ? 'true' : 'false'),
            is_int($value) => 'integer '.$value,
            is_float($value) => 'float '.$value,
            is_string($value) => 'string "'.$value.'"',
            is_array($value) => 'an array',
            default => 'an instance of '.get_debug_type($value),
        };
    }
}
