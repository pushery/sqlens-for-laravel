<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Catalog\RuleRegistryExport;

/**
 * Renders the parity list: what SQLens does about every rule the tool has.
 *
 * An honesty instrument. Coverage honesty is a stated goal of this package rather than a side
 * effect, and a comparison table that only lists the wins is the ordinary way that goal is
 * quietly abandoned — nobody writes down the gaps, so nobody sees them, and the omission never
 * looks like a decision.
 *
 * GENERATED, never maintained. A hand-written list drifts the moment the map changes, and a
 * drifted parity list is worse than none: it is a claim about coverage that nobody re-checked.
 * There is no timestamp anywhere in the output, so two runs produce the same bytes and any
 * change in it is a change in the map.
 */
final readonly class SquawkParityRenderer
{
    /** What each status means, in the package's own words — the legend a reader needs first. */
    private const array LEGEND = [
        'covered' => 'SQLens has a rule that reaches the same verdict on the same statement. '
            .'The tool\'s finding is recorded as a confirmation rather than reported twice.',
        'covered_differently' => 'SQLens covers the same ground from a different angle. Both '
            .'findings can appear, because they are two pieces of advice about one statement.',
        'mapped_only' => 'SQLens has no rule of its own here. The tool\'s finding is reported '
            .'under its own identifier — this is the coverage the amplifier adds.',
        'intentionally_not_covered' => 'SQLens deliberately does not report this, and the '
            .'reasoning is in the row. A decision on the record, not a gap nobody noticed.',
    ];

    /**
     * @param  list<string>  $ruleIds  every rule id this build ships, for the counts in the section
     *                                 below. Passed in rather than read here so the renderer keeps
     *                                 no opinion about where the catalog lives — and so the counts
     *                                 are DERIVED rather than a sentence somebody typed once.
     *
     * REQUIRED, with no default. An empty default would have rendered every count as zero — a page
     * announcing that SQLens has no rules at all, fluent and plausible and the worst sentence on the
     * site. A parameter that can be forgotten is one that will be; {@see self::shipped()} is the way
     * to build this.
     */
    public function __construct(private SquawkRuleMap $map, private array $ruleIds) {}

    /**
     * The renderer with the shipped catalog behind it — the form every caller wants.
     *
     * A constructor default of `[]` would render every count as zero, which is a page saying SQLens
     * has no rules at all. Named here so nobody assembles it wrong: the counts and the map travel
     * together or the page is a comparison against nothing.
     */
    public static function shipped(SquawkRuleMap $map): self
    {
        /** @var array{entries?: list<array{id: string}>} $registry */
        $registry = json_decode(
            (string) file_get_contents(dirname(__DIR__, 3).'/'.RuleRegistryExport::BUNDLED_FILE),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        return new self($map, array_column($registry['entries'] ?? [], 'id'));
    }

    public function render(): string
    {
        return implode("\n", [
            $this->frontMatter(),
            $this->preamble(),
            $this->legend(),
            $this->table(),
            $this->otherDirection(),
            '',
        ]);
    }

    /**
     * The half a coverage table leaves out, and the reason this one is not a self-diminishment.
     *
     * A parity list compares SQLens against a tool that reads `.sql` files, and it therefore
     * compares on that tool's ground. Everything SQLens does that has no `.sql` equivalent is
     * invisible in the table above — not because it is uncovered, but because there is nothing on
     * the other side to line it up against.
     *
     * The numbers are COUNTED from the shipped catalog rather than written down. A sentence saying
     * "dozens of rules" is a claim with no owner: nothing fails when it stops being true, and a
     * comparison page is exactly where an unowned number does damage.
     */
    private function otherDirection(): string
    {
        $prefixed = fn (string $prefix): int => count(
            array_filter($this->ruleIds, static fn (string $id): bool => str_starts_with($id, $prefix)),
        );

        return implode("\n", [
            '',
            '## What is not in the table above',
            '',
            'This page compares SQLens against a tool that reads `.sql` files, so it compares on that '
            .'ground. Everything below has no counterpart there — not because Squawk covers it badly, '
            .'but because a file of SQL is not where the question lives.',
            '',
            sprintf(
                '- **The migration, not the statement.** Whether `down()` exists, whether it really '
                .'inverts `up()`, whether it is more destructive than the migration it reverses. '
                .'%d driver-neutral rules judge the migration as a unit, and a `.sql` file has no '
                .'`down()` to judge.',
                $prefixed('GEN.'),
            ),
            sprintf(
                '- **The deploy, not the file.** %d checks run against the real target database at '
                .'deploy time and afterwards: the locks currently held, replication lag, disk '
                .'headroom, and — once the migration has run — the indexes that came out invalid '
                .'and the constraints that were never validated.',
                $prefixed('DEPLOY.'),
            ),
            '- **The database that already exists.** The audit suite reads the live catalog rather '
            .'than pending changes: a foreign key nobody indexed, a column type that was a mistake '
            .'three years ago, drift between what the migrations describe and what the server holds. '
            .'None of that is in any file.',
            sprintf(
                '- **MySQL at all.** Squawk is PostgreSQL-only. %d MySQL rules ship here, reasoning '
                .'about MySQL 8.4 semantics — the online-DDL algorithms, the privilege model, the '
                .'charset traps — against a shipped matrix rather than a guess.',
                $prefixed('MY.'),
            ),
            '',
            'The point of the table above is that the gaps are visible. The point of this section is '
            .'that the comparison is not the whole measurement.',
        ]);
    }

    private function frontMatter(): string
    {
        return implode("\n", [
            '---',
            'title: >-',
            '  Squawk parity',
            'description: >-',
            '  Every rule Squawk has, and what SQLens does about it — covered, covered differently, '
                .'reported as the tool\'s own, or deliberately not covered.',
            'sidebar_position: 35',
            '---',
            '',
        ]);
    }

    private function preamble(): string
    {
        return implode("\n", [
            sprintf(
                'SQLens treats [Squawk](https://squawkhq.com) as an amplifier, not a competitor. '
                .'It runs the tool over the same SQL it captured, maps what comes back into its own '
                .'rules and levels, and reports one finding where both saw one problem. This page '
                .'says exactly where that leaves each of the %d rules Squawk %s knows.',
                count($this->map->rules()),
                $this->map->measuredAgainst,
            ),
            '',
            'It is generated from the rule map that ships with the package, so it cannot drift from '
                .'what the code actually does. The reasoning in every row is written here; none of '
                .'the upstream wording is carried over.',
            '',
        ]);
    }

    private function legend(): string
    {
        $lines = ['## What the statuses mean', ''];

        foreach (self::LEGEND as $status => $meaning) {
            $lines[] = sprintf('- **`%s`** — %s', $status, $meaning);
        }

        $lines[] = '';

        return implode("\n", $lines);
    }

    private function table(): string
    {
        $lines = [
            '## The rules',
            '',
            '| Squawk rule | Status | SQLens rule | Why |',
            '|---|---|---|---|',
        ];

        // Iterated over the mappings themselves rather than over rules() + for(). The two are the
        // same data — rules() IS array_keys(mappings) — so a null check on the lookup guarded a
        // state that cannot occur, and an unreachable branch is not a safety net: it is a line no
        // test can ever cover and every reader has to reason about.
        foreach ($this->map->mappings as $rule => $mapping) {
            $lines[] = sprintf(
                '| [`%s`](%s) | `%s` | %s | %s |',
                $rule,
                $mapping->sourceUrl,
                $mapping->parityStatus->value,
                $mapping->sqlensRule === null ? '—' : '`'.$mapping->sqlensRule.'`',
                // Pipes would end the cell early. Nothing in the map carries one today, and a row
                // that silently lost half its reasoning is not the way to find out that changed.
                str_replace('|', '\\|', $mapping->rationale),
            );
        }

        // Deliberately NO trailing '' here, unlike legend() above. legend()'s one creates the blank
        // line BETWEEN the sections, which is right. render() then appends a final '' of its own — so
        // a second one here made the page end `|\n\n`, and markdownlint reports that as
        // MD012/no-multiple-blanks. Each half read correctly on its own; the SEAM did not, and the
        // docs lint failed on every push because of it.
        return implode("\n", $lines);
    }
}
