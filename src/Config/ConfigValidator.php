<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * Walks the raw `sqlens` config array against the ConfigSchema and collects
 * EVERY violation — unknown keys, missing keys, wrong types, out-of-range
 * values — never stopping at the first. Any violation means the run exits
 * with the misconfiguration code before a single check executes: a config the
 * user believes in but the tool silently ignores is the most expensive kind of
 * green there is.
 *
 * The walk order is deterministic: schema keys in declared order first (missing
 * keys and value violations), then the unknown keys in the order the config
 * array holds them — same config, same list, byte for byte.
 */
final class ConfigValidator
{
    public function __construct(private readonly ConfigSchema $schema = new ConfigSchema) {}

    /**
     * Notices gathered by the walk in progress.
     *
     * Mutable state on an otherwise stateless object, and deliberately narrow: the walk is
     * recursive over sections, so a return-value accumulator would have to be threaded through
     * five signatures that exist to answer a different question. It is reset at the top of
     * {@see inspect()}, so two inspections never see each other.
     *
     * @var list<ConfigViolation>
     */
    private array $notices = [];

    /**
     * Validate the value of `config('sqlens')`. An empty list means the config
     * is valid; a non-empty list maps to ExitCode::Misconfiguration.
     *
     * The narrower of the two doors, kept because most callers only ever ask the fatal question.
     * It delegates rather than walking again — see {@see ConfigInspection}.
     *
     * @return list<ConfigViolation>
     */
    public function validate(mixed $config): array
    {
        return $this->inspect($config)->violations;
    }

    /**
     * One walk, both answers: what stops the run, and what merely applies a default.
     *
     * ## An absent schema key is a NOTICE, not a violation
     *
     * It used to be fatal everywhere except one opt-in root, and that was measured to be an
     * upgrade breaker: `mergeConfigFrom()` is a shallow merge, so an application that published
     * `config/sqlens.php` before a release added a nested key has that key missing permanently.
     * Every `sqlens:*` command then exited on misconfiguration — a package release nobody could
     * install without hand-editing a file.
     *
     * The protection that was traded away is real and is named rather than dropped: a published
     * copy that lost a whole section now runs on defaults the project believes it overrode. It
     * says so, once per key, in the notice list — which is this package's usual move when it
     * cannot decide something for you: report it, do not pretend it did not happen.
     *
     * The half that was actually load-bearing is untouched. An UNKNOWN key is still fatal,
     * because a typo that silently enables nothing is the failure this validator exists for.
     */
    public function inspect(mixed $config): ConfigInspection
    {
        if (! is_array($config)) {
            return new ConfigInspection([ConfigViolation::wrongType(
                'sqlens',
                'the sqlens configuration array — is the package installed and its config merged?',
                $config,
            )]);
        }

        $violations = [];
        $this->notices = [];

        foreach (ConfigSchema::TOP_LEVEL_KEYS as $key) {
            if (! array_key_exists($key, $config)) {
                $this->notices[] = ConfigViolation::defaultedKey('sqlens.'.$key, $this->schema->expectation($key));

                continue;
            }

            $violations = [...$violations, ...$this->keyViolations($key, $config[$key])];
        }

        foreach (array_keys($config) as $key) {
            $key = (string) $key;

            if (! in_array($key, ConfigSchema::TOP_LEVEL_KEYS, true)) {
                $violations[] = $this->unknownTopLevelKey($key);
            }
        }

        return new ConfigInspection($violations, $this->notices);
    }

    /** @return list<ConfigViolation> */
    private function keyViolations(string $key, mixed $value): array
    {
        if (array_key_exists(ConfigSchema::template($key), ConfigSchema::SECTION_KEYS)) {
            return $this->sectionViolations($key, $value);
        }

        if ($key === 'ignore') {
            return $this->ignoreViolations($value);
        }

        if ($key === 'profiles') {
            return $this->profilesViolations($value);
        }

        return $this->schema->leafViolations($key, $value);
    }

    /**
     * Validate the `profiles` map. It is deliberately NOT a schema section: a
     * section demands every declared key be present, while a profile is a PARTIAL
     * override — naming only what the environment changes is the whole point, and
     * requiring all six everywhere would make three profiles into three copies of
     * the base config.
     *
     * What IS enforced: the profile name must be one SQLens knows (a typo must not
     * silently fall back to a lenient default), and every key inside must be one
     * of the overridable settings, validated against the SAME leaf spec as its
     * base-config counterpart — so a profile can never accept a value the root
     * would reject.
     *
     * @return list<ConfigViolation>
     */
    private function profilesViolations(mixed $value): array
    {
        if (! is_array($value)) {
            return [ConfigViolation::wrongType('sqlens.profiles', $this->schema->expectation('profiles'), $value)];
        }

        $known = $this->schema->profileNames();
        $violations = [];

        foreach ($value as $name => $overrides) {
            $name = (string) $name;

            if (! in_array($name, $known, true)) {
                $violations[] = ConfigViolation::unknownKey('sqlens.profiles.'.$name, $known);

                continue;
            }

            if (! is_array($overrides)) {
                $violations[] = ConfigViolation::wrongType('sqlens.profiles.'.$name, $this->schema->expectation('profile-entry'), $overrides);

                continue;
            }

            $violations = [...$violations, ...$this->overrideViolations('sqlens.profiles.'.$name, '', $overrides)];
        }

        return $violations;
    }

    /**
     * Walk one profile's overrides. `$prefix` is the dotted path reached so far
     * (empty at the top), so a nested `security` => `min_severity` validates
     * against exactly the root path `security.min_severity`.
     *
     * The allowed shape is DERIVED from the overridable list rather than listed a
     * second time: a key is a leaf if the path it completes is overridable, a
     * branch if some overridable path starts with it, and unknown otherwise.
     *
     * @param  array<array-key, mixed>  $overrides
     * @return list<ConfigViolation>
     */
    private function overrideViolations(string $path, string $prefix, array $overrides): array
    {
        $violations = [];

        foreach ($overrides as $key => $item) {
            $key = (string) $key;
            $relative = $prefix === '' ? $key : $prefix.'.'.$key;

            if (in_array($relative, ConfigSchema::PROFILE_OVERRIDABLE, true)) {
                $violations = [...$violations, ...$this->rebased($path.'.'.$key, $this->schema->leafViolations($relative, $item))];

                continue;
            }

            if ($this->isOverridableBranch($relative)) {
                $violations = is_array($item)
                    ? [...$violations, ...$this->overrideViolations($path.'.'.$key, $relative, $item)]
                    : [...$violations, ConfigViolation::wrongType($path.'.'.$key, $this->schema->expectation($relative), $item)];

                continue;
            }

            $violations[] = ConfigViolation::unknownKey($path.'.'.$key, ConfigSchema::PROFILE_OVERRIDABLE);
        }

        return $violations;
    }

    /** Whether some overridable path continues below this one (so it is a branch, not a typo). */
    private function isOverridableBranch(string $relative): bool
    {
        return array_any(
            ConfigSchema::PROFILE_OVERRIDABLE,
            static fn (string $overridable): bool => str_starts_with($overridable, $relative.'.'),
        );
    }

    /**
     * Re-point violations produced against a ROOT path at the profile path they
     * actually came from — see {@see ConfigViolation::at()}.
     *
     * @param  list<ConfigViolation>  $violations
     * @return list<ConfigViolation>
     */
    private function rebased(string $path, array $violations): array
    {
        return array_map(
            static fn (ConfigViolation $violation): ConfigViolation => $violation->at($path),
            $violations,
        );
    }

    /** @return list<ConfigViolation> */
    private function sectionViolations(string $section, mixed $value): array
    {
        if (! is_array($value)) {
            return [ConfigViolation::wrongType('sqlens.'.$section, $this->schema->expectation($section), $value)];
        }

        // A WILDCARD section: the keys are names a project chose, so there is nothing to check them
        // against — but everything inside each one is checked against a single template. Handled
        // before the fixed-key path rather than inside it, because the two answer opposite
        // questions: down there an unlisted key is a typo, and up here it is the whole point.
        if (array_key_exists($section, ConfigSchema::WILDCARD_SECTIONS)) {
            $violations = [];

            foreach ($value as $name => $entry) {
                $violations = [...$violations, ...$this->sectionViolations(
                    $section.'.'.$name,
                    $entry,
                )];
            }

            return $violations;
        }

        $violations = [];
        $sectionKeys = ConfigSchema::SECTION_KEYS[ConfigSchema::template($section)];

        foreach ($sectionKeys as $key) {
            $relativePath = $section.'.'.$key;

            if (! array_key_exists($key, $value)) {
                $this->notices[] = ConfigViolation::defaultedKey('sqlens.'.$relativePath, $this->schema->expectation($relativePath));

                continue;
            }

            // A key that is itself a declared section recurses; anything else is a
            // leaf. This is what lets `capture.session.*` exist without the schema
            // growing a second, parallel notion of depth.
            $violations = [...$violations, ...(array_key_exists(ConfigSchema::template($relativePath), ConfigSchema::SECTION_KEYS)
                || array_key_exists($relativePath, ConfigSchema::WILDCARD_SECTIONS)
                ? $this->sectionViolations($relativePath, $value[$key])
                : $this->schema->leafViolations($relativePath, $value[$key]))];
        }

        foreach (array_keys($value) as $key) {
            $key = (string) $key;

            if (! in_array($key, $sectionKeys, true)) {
                $violations[] = ConfigViolation::unknownKey('sqlens.'.$section.'.'.$key, $sectionKeys);
            }
        }

        return [...$violations, ...$this->crossKeyViolations($section, $value)];
    }

    /**
     * The checks that need TWO keys of one section in hand at once.
     *
     * Deliberately here and not in the schema: a leaf rule is asked about one value and cannot see
     * its neighbor, and giving it the whole section would make every rule able to reach anywhere.
     * There is one such rule today, and it exists because the value it guards is the entire point
     * of the mode it belongs to.
     *
     * @param  array<array-key, mixed>  $value
     * @return list<ConfigViolation>
     */
    private function crossKeyViolations(string $section, array $value): array
    {
        if ($section !== 'security.rls' || ($value['mode'] ?? null) !== 'application') {
            return [];
        }

        $reason = $value['reason'] ?? null;

        // `application` says separation happens somewhere this package cannot read. The sentence IS
        // the answer — without it the mode would be a way to silence the check while saying nothing,
        // which is the one thing the whole SEC.RLS family refuses.
        return is_string($reason) && trim($reason) !== ''
            ? []
            : [ConfigViolation::missingKey(
                'sqlens.security.rls.reason',
                'a sentence saying how separation is enforced, because the mode is `application`',
            )];
    }

    /** @return list<ConfigViolation> */
    private function ignoreViolations(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return [ConfigViolation::wrongType('sqlens.ignore', $this->schema->expectation('ignore'), $value)];
        }

        $violations = [];

        foreach ($value as $index => $entry) {
            $entryPath = 'sqlens.ignore.'.$index;

            if (! is_array($entry)) {
                $violations[] = ConfigViolation::wrongType($entryPath, $this->schema->expectation('ignore-entry'), $entry);

                continue;
            }

            foreach (ConfigSchema::IGNORE_ENTRY_REQUIRED as $required) {
                if (! array_key_exists($required, $entry)) {
                    $violations[] = ConfigViolation::missingKey($entryPath.'.'.$required, $this->schema->expectation('ignore.'.$required));
                }
            }

            foreach ($entry as $field => $fieldValue) {
                $field = (string) $field;

                if (! in_array($field, ConfigSchema::IGNORE_ENTRY_KEYS, true)) {
                    $violations[] = ConfigViolation::unknownKey($entryPath.'.'.$field, ConfigSchema::IGNORE_ENTRY_KEYS);

                    continue;
                }

                $violations = [...$violations, ...$this->schema->ignoreFieldViolations($entryPath.'.'.$field, $field, $fieldValue)];
            }
        }

        return $violations;
    }

    /**
     * An unknown top-level key — with one special case: a dotted key whose
     * dot-expansion IS a known path gets the dot-notation-trap message with the
     * exact nested rewrite instead of a generic "unknown key".
     */
    private function unknownTopLevelKey(string $key): ConfigViolation
    {
        if (str_contains($key, '.') && $this->schema->isKnownPath($key)) {
            return ConfigViolation::dottedLiteralKey($key);
        }

        return ConfigViolation::unknownKey('sqlens.'.$key, ConfigSchema::TOP_LEVEL_KEYS);
    }
}
