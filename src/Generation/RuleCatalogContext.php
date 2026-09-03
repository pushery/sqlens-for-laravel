<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

/**
 * WHICH world a rule catalog describes.
 *
 * A list of rules is not preventive knowledge on its own — the same package answers with a
 * different set at level 0 and level 4, on PostgreSQL and on MySQL, with and without a version
 * pin. A catalog that shipped only the rules would be read as "this is what SQLens checks",
 * which is true of no configuration in particular.
 *
 * So every axis that narrowed the set is carried beside it, and every one of them goes into the
 * snapshot's hash. Two catalogs that differ only in their pin must not look identical: the marker
 * line a renderer writes is compared by hash, and a `--check` that could not see a changed pin
 * would report a file as current after the world it describes had moved.
 */
final readonly class RuleCatalogContext
{
    /**
     * @param  list<string>  $categories  the category values in force, empty meaning all of them
     * @param  list<string>  $stability  the tiers admitted, always including the stable one
     * @param  string|null  $serverVersion  the pin, or null when nothing is pinned
     * @param  string|null  $minSeverity  the security floor, or null when the axis is off
     * @param  list<string>  $ignoredRuleIds  rules this project switched off project-wide
     */
    public function __construct(
        public string $driver,
        public string $profile,
        public int $level,
        public array $categories,
        public array $stability,
        public ?string $serverVersion,
        public ?string $minSeverity,
        public array $ignoredRuleIds,
    ) {}

    /**
     * The context as fixed-order data.
     *
     * `server_version_source` is stated rather than left to be inferred from a null. "No version"
     * and "version 18.0" are different facts, but so are "nobody pinned one" and "one was pinned
     * and it happens to be absent from this shape later" — naming the source keeps a reader from
     * having to guess which null they are looking at.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'driver' => $this->driver,
            'profile' => $this->profile,
            'level' => $this->level,
            'categories' => $this->categories,
            'stability' => $this->stability,
            'server_version' => $this->serverVersion,
            'server_version_source' => $this->serverVersion === null ? 'none' : 'pin',
            'min_severity' => $this->minSeverity,
            'ignored_rule_ids' => $this->ignoredRuleIds,
        ];
    }

    /**
     * The sentence a renderer puts above the rules when no version is pinned.
     *
     * Null when one is, because a note that is always present is one nobody reads. It says what
     * was NOT established rather than apologizing: a version-dependent rule below is in the list
     * because it could not be placed, and the reader is the only one who can place it.
     */
    public function versionNote(): ?string
    {
        if ($this->serverVersion !== null) {
            return null;
        }

        return 'No server version is pinned, so rules with a version window could not be placed. '
            .'They are listed and marked version-dependent rather than assumed to apply — set '
            .'sqlens.assume_server_version to resolve them.';
    }
}
