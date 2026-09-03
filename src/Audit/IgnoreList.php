<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * Which audit findings a project has asked not to be gated on — a pure predicate over the
 * configured lists, with no knowledge of findings, results or reporting.
 *
 * ## Why it decides nothing about visibility
 *
 * It answers one question: does this project's configuration name this rule on this object. What
 * happens to a finding that matches is the suppression machinery's business, and that machinery
 * already COUNTS and LISTS what it hides. Keeping the two apart is what stops this from becoming a
 * second, quieter way to make findings disappear: a list that deleted findings itself would report
 * "clean" over a database with twelve known problems, which is the exact leak the ignore list is
 * meant to be an alternative to.
 *
 * ## The three forms, and why the precise one is the recommended one
 *
 * - `rules` silences a rule everywhere. Blunt, and honest about being blunt.
 * - `objects` silences every rule on a path. Useful for a legacy schema nobody will fix.
 * - `pairs` silences ONE rule on named paths, and is the form to reach for: the other two grow
 *   silently. A rule ignored project-wide keeps ignoring itself on tables added next year, and a
 *   schema ignored wholesale hides rules that did not exist when somebody wrote the line.
 *
 * ## Path matching
 *
 * A path is dot-separated and increasingly specific — `schema`, `schema.table`,
 * `schema.table.column`. A pattern is the same shape, and a segment may end in `*` to match a
 * prefix within THAT segment only. The glob never crosses a dot, which is the property that makes
 * a pattern's blast radius readable: `public.orders` cannot reach `public.orders_archive`, because
 * segments match whole.
 *
 * A pattern matches a path when every one of its segments matches the path's corresponding
 * segment. A path MAY be longer than its pattern — `public.orders` covers `public.orders.total`,
 * since ignoring a table means ignoring what is in it — but never shorter, so `public.orders` does
 * not silence a finding about the `public` schema itself.
 *
 * ## File-located objects, where dots are not separators
 *
 * Not every subject lives in a schema. An HBA finding is located in a FILE, and its object name is
 * a path with a line number:
 *
 *     /etc/postgresql/18/main/pg_hba.conf:117
 *
 * Splitting that on dots produces two meaningless halves (`/etc/…/pg_hba` and `conf:117`), so a
 * project with ONE deliberately accepted `trust` line could only reach it through a pattern like
 * `*.conf:117` — or had to fall back to `rules` and silence the rule everywhere, which is the blunt
 * instrument this list exists to offer an alternative to.
 *
 * **A pattern containing `/` is matched against the WHOLE path instead**, with `*` free to cross
 * both dots and slashes. The switch is a property of the pattern the author wrote, never a guess
 * about the data: a schema path never contains a slash, so no existing pattern changes meaning, and
 * an author who writes a file path gets file semantics because that is plainly what they meant.
 *
 * It also makes the obvious thing work — copying the object name straight out of the report:
 *
 *     objects: ['/etc/postgresql/18/main/pg_hba.conf:117']   // that one line
 *     objects: ['/etc/postgresql/18/main/pg_hba.conf:*']     // every line of that file
 *
 * The blast radius stays readable for the same reason as above: `*` is the only wildcard, and
 * everything else matches literally.
 *
 * ## The table prefix
 *
 * An application with a configured prefix stores `wp_orders` and writes `orders` everywhere in its
 * own code. A pattern is therefore matched with AND without the prefix, so both spellings work.
 * The alternative — demanding the stored name — would make every ignore line in a prefixed project
 * disagree with the migration it refers to, and the first person to copy a table name out of a
 * model would write a line that silently matches nothing.
 */
final readonly class IgnoreList
{
    /** The three forms, named once so a report and a config file spell them the same way. */
    public const string FORM_RULES = 'rules';

    public const string FORM_OBJECTS = 'objects';

    public const string FORM_PAIRS = 'pairs';

    /**
     * @param  list<string>  $rules  rule ids silenced everywhere
     * @param  list<string>  $objects  paths on which every rule is silenced
     * @param  list<array{rule: string, objects: list<string>}>  $pairs  one rule, named paths
     * @param  string  $tablePrefix  the application's table prefix, so a pattern may omit it
     */
    private function __construct(
        public array $rules,
        public array $objects,
        public array $pairs,
        private string $tablePrefix = '',
    ) {}

    /** An empty list — the default, and the state of a project that has ignored nothing. */
    public static function empty(): self
    {
        return new self([], [], []);
    }

    /**
     * Build from whatever `sqlens.audit.ignore` holds, however malformed.
     *
     * Malformed entries are dropped rather than refused, because refusing is the config
     * validator's job and it runs before this does. What must never happen here is the opposite
     * failure: a value this class could not read must not silence MORE than it says. Every
     * narrowing below therefore drops toward the empty list, never toward a wildcard.
     */
    public static function fromConfig(mixed $config, string $tablePrefix = ''): self
    {
        if (! is_array($config)) {
            return new self([], [], [], $tablePrefix);
        }

        return new self(
            self::strings($config['rules'] ?? null),
            self::strings($config['objects'] ?? null),
            self::pairs($config['pairs'] ?? null),
            $tablePrefix,
        );
    }

    /**
     * Every rule id this list names, with the form and position it was written at.
     *
     * For the validator, which turns an unknown id into a configuration error rather than letting
     * it sit there matching nothing. That failure mode is the expensive one: a typo means the rule
     * keeps firing while the project believes it is off, and they read past its findings for
     * months. A pattern that matches nothing looks exactly like a pattern whose findings are gone.
     *
     * Object patterns are not here — they name no rule, and their own validation is a different
     * question with a different answer.
     *
     * @return list<array{ruleId: string, form: string, index: int}>
     */
    public function ruleReferences(): array
    {
        $references = [];

        foreach ($this->rules as $index => $ruleId) {
            $references[] = ['ruleId' => $ruleId, 'form' => self::FORM_RULES, 'index' => $index];
        }

        foreach ($this->pairs as $index => $pair) {
            $references[] = ['ruleId' => $pair['rule'], 'form' => self::FORM_PAIRS, 'index' => $index];
        }

        return $references;
    }

    /** Whether the project has configured nothing — so a caller can skip the work entirely. */
    public function isEmpty(): bool
    {
        return $this->rules === [] && $this->objects === [] && $this->pairs === [];
    }

    /**
     * WHICH form covers this rule on this object — `rules`, `objects`, `pairs` — or null.
     *
     * The form rather than a bare yes, because a report that says "12 suppressed" and one that
     * says "12 suppressed (9 by rule, 3 by object)" answer different questions. The first tells a
     * reader that something is hidden; the second tells them how it got that way, which is what
     * they need to decide whether the list has grown past what anyone intended. A rule silenced
     * project-wide and a single table silenced on purpose are very different states of a project,
     * and only the breakdown can tell them apart.
     *
     * The object path is nullable because a run-level notice is about no object at all. Such a
     * finding can only be reached by the `rules` form: an object pattern that matched a finding
     * with no object would be silencing something the pattern's author never described.
     */
    public function matchedForm(string $ruleId, ?string $objectPath): ?string
    {
        if (in_array($ruleId, $this->rules, true)) {
            return self::FORM_RULES;
        }

        if ($objectPath === null) {
            return null;
        }

        foreach ($this->objects as $pattern) {
            if ($this->matches($pattern, $objectPath)) {
                return self::FORM_OBJECTS;
            }
        }

        foreach ($this->pairs as $pair) {
            if ($pair['rule'] !== $ruleId) {
                continue;
            }

            foreach ($pair['objects'] as $pattern) {
                if ($this->matches($pattern, $objectPath)) {
                    return self::FORM_PAIRS;
                }
            }
        }

        return null;
    }

    /**
     * Object patterns that matched none of the paths this run actually read.
     *
     * An orphan is not an error: a pattern may legitimately point at a table that does not exist
     * yet, or at one somebody finally dropped. It is DEBT, and debt that nobody can see is the
     * kind that stays. The dangerous property is that an orphaned pattern is indistinguishable
     * from a working one — both produce a report without those findings — so the only way a
     * project learns its ignore list has rotted is by being told.
     *
     * Patterns from `pairs` are included: the rule they name is checked separately, and a pair
     * whose OBJECT no longer exists is as orphaned as a bare one.
     *
     * @param  list<string>  $paths  the object paths this run read
     * @return list<string> the patterns that covered none of them
     */
    public function orphanedObjectPatterns(array $paths): array
    {
        $patterns = $this->objects;

        foreach ($this->pairs as $pair) {
            foreach ($pair['objects'] as $pattern) {
                $patterns[] = $pattern;
            }
        }

        $orphans = [];

        foreach (array_values(array_unique($patterns)) as $pattern) {
            foreach ($paths as $path) {
                if ($this->matches($pattern, $path)) {
                    continue 2;
                }
            }

            $orphans[] = $pattern;
        }

        // Sorted, so two runs over one state report one list — the header has to be byte-stable.
        sort($orphans);

        return $orphans;
    }

    /** Whether any form covers it — the predicate, for callers that do not care which. */
    public function ignores(string $ruleId, ?string $objectPath): bool
    {
        return $this->matchedForm($ruleId, $objectPath) !== null;
    }

    /** Whether one pattern covers one path, segment by segment — or whole, for a file path. */
    private function matches(string $pattern, string $path): bool
    {
        // A slash in the PATTERN selects whole-path matching. Read off the pattern rather than the
        // path on purpose: the author writes the shape they mean, and a schema path never carries a
        // slash, so no pattern written before this existed can change meaning.
        if (str_contains($pattern, '/')) {
            return $this->matchesWholePath($pattern, $path);
        }

        $patternSegments = explode('.', $pattern);
        $pathSegments = explode('.', $path);

        // A path shorter than its pattern is a LESS specific thing than the pattern describes, and
        // silencing it would widen the pattern beyond what its author wrote.
        if (count($pathSegments) < count($patternSegments)) {
            return false;
        }

        return array_all($patternSegments, fn (string $segment, int $index): bool => $this->segmentMatches($segment, $pathSegments[$index]));
    }

    /**
     * One file-located pattern against one whole path, with `*` free to cross dots and slashes.
     *
     * Built from `preg_quote` plus one substitution rather than `fnmatch`: fnmatch is not available
     * on every platform this package supports, and its `*` refuses to cross a `/` — the one thing a
     * pattern like `/etc/postgresql/18/main/pg_hba.conf:*` needs it to do. The match is anchored at
     * both ends, so a pattern names the whole object and cannot silence a longer one by accident.
     *
     * The table prefix is deliberately NOT consulted here. It exists because an application writes
     * `orders` where the database stores `wp_orders`; a file on the server's disk has no such second
     * spelling, and applying it would invent one.
     */
    private function matchesWholePath(string $pattern, string $path): bool
    {
        return preg_match('/^'.str_replace('\*', '.*', preg_quote($pattern, '/')).'$/', $path) === 1;
    }

    /** One segment against one segment: a literal, or a literal followed by `*`. */
    private function segmentMatches(string $pattern, string $segment): bool
    {
        if (! str_ends_with($pattern, '*')) {
            return $pattern === $segment || $this->prefixed($pattern) === $segment;
        }

        $head = substr($pattern, 0, -1);

        return str_starts_with($segment, $head) || str_starts_with($segment, $this->prefixed($head));
    }

    /** The same name as the application stores it — unchanged when there is no prefix. */
    private function prefixed(string $name): string
    {
        return $this->tablePrefix.$name;
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        return is_array($value)
            ? array_values(array_filter($value, is_string(...)))
            : [];
    }

    /**
     * @return list<array{rule: string, objects: list<string>}>
     */
    private static function pairs(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $pairs = [];

        foreach ($value as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            if (! is_string($entry['rule'] ?? null)) {
                continue;
            }
            $objects = self::strings($entry['objects'] ?? null);

            // A pair with no objects is dropped rather than read as "this rule, everywhere". The
            // other reading is available and spelled `rules:`; treating an empty list as a wildcard
            // would turn a half-written line into a project-wide silence.
            if ($objects === []) {
                continue;
            }

            $pairs[] = ['rule' => $entry['rule'], 'objects' => $objects];
        }

        return $pairs;
    }
}
