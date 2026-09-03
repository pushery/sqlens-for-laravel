<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * The engine-specific sentence a driver-neutral rule adds to its finding.
 *
 * Some hazards are the same on both engines and land differently. A missing `down()` is a missing
 * `down()` anywhere — but on MySQL every DDL statement causes an implicit commit, so a failed `up()`
 * leaves a partially applied schema and `down()` is not a safety net at all, it is a manual teardown
 * script. Saying only the neutral half there is not wrong, it is just less than the reader needs.
 *
 * ## Why this is DATA and not a branch in the rule
 *
 * The obvious implementation is `if ($driver === 'mysql')` inside the rule, and it is the wrong one
 * twice over. It makes a rule that is meant to be driver-neutral know an engine by name — the exact
 * coupling the architecture guards forbid in Core — and it spreads engine truth across as many files
 * as there are rules, where the next engine has to find every one of them.
 *
 * Kept as a register instead, the engine truth sits in one reviewable file beside the evidence and
 * example registers, a rule stays neutral, and a new driver adds rows rather than editing rules.
 *
 * ## What a note is NOT
 *
 * It never changes the verdict, the level, the class or the reason — only the prose a human reads.
 * A note that decided anything would be a second rule hiding in a data file, unreachable from the
 * rule's own tests. It is also never the ONLY thing that carries a fact: an engine difference that
 * changes what the tool concludes belongs in a rule of its own, not in a sentence.
 */
final readonly class RuleDriverNotes
{
    /** Where the register lives, relative to the package root. */
    public const string BUNDLED_FILE = 'resources/data/rule-driver-notes.json';

    /** The format this reader implements. An unknown version in the file is an error. */
    public const int SCHEMA_VERSION = 1;

    /** @param  array<string, array<string, string>>  $notes  rule id => driver key => note */
    private function __construct(private array $notes) {}

    public static function bundled(): self
    {
        return self::fromFile(dirname(__DIR__, 2).'/'.self::BUNDLED_FILE);
    }

    /** Read a register file, failing loudly on anything malformed — never a silently empty set. */
    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidRuleEvidence::unreadable(self::BUNDLED_FILE);
        }

        /** @var mixed $decoded */
        $decoded = json_decode($raw, true);

        if (! is_array($decoded) || ($decoded['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw InvalidRuleEvidence::malformed(self::BUNDLED_FILE, 'schema_version', (string) self::SCHEMA_VERSION);
        }

        $entries = $decoded['entries'] ?? null;

        if (! is_array($entries)) {
            throw InvalidRuleEvidence::malformed(self::BUNDLED_FILE, 'entries', 'an object keyed by rule id');
        }

        $notes = [];

        foreach ($entries as $ruleId => $perDriver) {
            if (! is_string($ruleId) || ! is_array($perDriver)) {
                throw InvalidRuleEvidence::malformed(self::BUNDLED_FILE, 'entries', 'a rule id mapping to an object keyed by driver');
            }

            foreach ($perDriver as $driver => $note) {
                if (! is_string($driver) || ! is_string($note) || trim($note) === '') {
                    throw InvalidRuleEvidence::malformed(self::BUNDLED_FILE, "entries.{$ruleId}", 'a driver key mapping to a non-empty note');
                }

                $notes[$ruleId][$driver] = $note;
            }
        }

        return new self($notes);
    }

    /**
     * An explicit set, for a test that pins behavior without a file.
     *
     * @param  array<string, array<string, string>>  $notes  rule id => driver key => note
     */
    public static function fromArray(array $notes): self
    {
        return new self($notes);
    }

    /** The note for a rule on a driver, or null when there is none — the ordinary case. */
    public function for(string $ruleId, string $driver): ?string
    {
        return $this->notes[$ruleId][$driver] ?? null;
    }

    /**
     * A message with its engine note appended, or the message unchanged.
     *
     * Appended rather than woven in: the neutral sentence stays the same on every engine, so two
     * readers comparing a PostgreSQL and a MySQL report see one text plus a difference, rather than
     * two texts they have to diff to find the difference.
     */
    public function apply(string $message, string $ruleId, string $driver): string
    {
        $note = $this->for($ruleId, $driver);

        return $note === null ? $message : $message.' '.$note;
    }

    /** @return array<string, array<string, string>> the whole register, for a completeness test */
    public function all(): array
    {
        return $this->notes;
    }
}
