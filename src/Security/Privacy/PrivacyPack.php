<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Illuminate\Contracts\Config\Repository as Config;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Rule;

/**
 * Whether the privacy rules run at all, and what they are told when they do.
 *
 * ## Off by default, and off is a decision
 *
 * These rules read column NAMES and guess what lives in them. That is a useful guess and an
 * unreliable one: a column called `iban` usually holds an IBAN and sometimes holds a label. A pack
 * that guessed wrong by default would teach a team to ignore the category it guessed in, and a
 * category people ignore is worse than one that never ran — it is a category that will still be
 * ignored on the day it is right.
 *
 * ## Not registered, rather than registered and skipped
 *
 * Switched off, the rules never enter the registry. They cost no query, no scan and no time — the
 * run does not carry them and quietly pass over them, it does not have them.
 *
 * That is not the same as silence. The run reports which categories were active, so a report from a
 * project with the pack off says so, and a reader can tell "checked and found nothing" from "was
 * never asked". A suite that checked less has to say it checked less.
 */
final readonly class PrivacyPack
{
    public function __construct(private Config $config) {}

    /** Whether a project has deliberately switched the pack on. */
    public function isEnabled(): bool
    {
        return $this->config->get('sqlens.security.privacy.enabled') === true;
    }

    /**
     * The rules a run may register, with the privacy ones removed when the pack is off.
     *
     * A filter over any rule list rather than a lookup by id, so a privacy rule added later is
     * governed by this switch without anybody remembering to add it here. The alternative — a list
     * of ids to exclude — is the shape that goes stale the first time somebody writes a rule and
     * does not know the list exists.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function admitted(array $rules): array
    {
        if ($this->isEnabled()) {
            return $rules;
        }

        return array_values(array_filter(
            $rules,
            static fn (Rule $rule): bool => $rule->category() !== Category::Privacy,
        ));
    }

    /**
     * Terms this project adds to whichever dictionary is in force.
     *
     * @return list<string>
     */
    public function extraTerms(): array
    {
        return $this->stringList('sqlens.security.privacy.extra_terms');
    }

    /**
     * Qualified column names this project has looked at and decided about.
     *
     * Qualified, because `notes` is a different question on `orders` than on `patients` — the
     * config schema refuses an unqualified entry rather than silencing a column nobody considered.
     *
     * @return list<string>
     */
    public function ignoredColumns(): array
    {
        return $this->stringList('sqlens.security.privacy.ignore_columns');
    }

    /** A repository-relative dictionary path, or null for the bundled one. */
    public function dictionaryPath(): ?string
    {
        $configured = $this->config->get('sqlens.security.privacy.dictionary');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /**
     * @return list<string>
     */
    private function stringList(string $key): array
    {
        $configured = $this->config->get($key);

        if (! is_array($configured)) {
            return [];
        }

        return array_values(array_filter($configured, is_string(...)));
    }
}
