<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

use Pushery\SQLens\Generation\RuleCatalogSnapshot;

/**
 * The rules themselves, as prose an agent reads before it writes a migration.
 *
 * ## Why one body and three wrappers
 *
 * The three target formats differ in where the file goes, what frontmatter it carries and whether
 * it owns its file. They do NOT differ in what a project's rules are. Writing the body three times
 * would mean three descriptions of one rule set, and the day one of them gained a sentence the
 * other two would be quietly wrong — which is the same drift the whole export chain exists to
 * prevent, reproduced one layer down.
 *
 * ## Compact is shorter per rule, never fewer rules
 *
 * One target has a tighter practical budget than the others, so it gets a shorter line per rule.
 * It does not get a SUBSET: a rule missing from an agent's context is a rule that agent will break,
 * and it would break it silently, because the omission is invisible from inside the file.
 */
final readonly class RuleGuidance
{
    /**
     * The body, without frontmatter and without markers.
     *
     * @param  bool  $compact  one line per rule instead of a block; same rules either way
     */
    public static function body(RuleCatalogSnapshot $snapshot, bool $compact = false): string
    {
        $lines = [
            'These are the database rules this project has configured. They were generated from its '
                .'own SQLens configuration, so the list is this project\'s rather than a general one. What any '
                .'ONE run checks is a subset of it: the suite counts below say how many each carries, and a '
                .'rule its own configuration has switched off says so where it appears.',
            '',
            ...self::context($snapshot),
            '',
        ];

        foreach (self::byCategory($snapshot) as $category => $rows) {
            $lines[] = '## '.ucfirst(str_replace('_', ' ', $category));
            $lines[] = '';

            foreach ($rows as $row) {
                $lines = [...$lines, ...($compact ? self::compactRule($row) : self::fullRule($row))];
            }
        }

        return implode("\n", [...$lines, ...self::closing($snapshot->versionDependentIds !== [])]);
    }

    /**
     * The run's own parameters, so a reader can tell WHICH configuration this describes.
     *
     * The version note is included when there is one. A catalog produced without a pin lists rules
     * it could not place, and a reader who does not know that will treat every line as certain.
     *
     * @return list<string>
     */
    private static function context(RuleCatalogSnapshot $snapshot): array
    {
        $context = $snapshot->context;

        $lines = [
            '- **Engine:** '.$context->driver
                .' · **Level:** '.$context->level
                .' · **Server version:** '.($context->serverVersion ?? 'not pinned'),
            '- **Rules configured:** '.count($snapshot->entries)
                .($snapshot->versionDependentIds === [] ? '' : ', of which '.count($snapshot->versionDependentIds).' depend on the server version'),
            '- **By suite:** '.self::perSuite($snapshot)
                .' — a rule can belong to more than one suite, so these do not add up to the total.',
        ];

        $note = $context->versionNote();

        if ($note !== null) {
            $lines[] = '- **'.$note.'**';
        }

        return $lines;
    }

    /**
     * One rule, in full.
     *
     * The downtime class is here because it is the field that changes what somebody writes next,
     * and the documentation URL because inlining every rationale would make this longer than the
     * migrations it is about.
     *
     * @param  array<array-key, mixed>  $row
     * @return list<string>
     */
    private static function fullRule(array $row): array
    {
        return [
            '### '.self::text($row, 'id'),
            '',
            '- **Level '.self::text($row, 'level').'**'
                .self::suffix($row, 'severity', ' · Severity: ')
                .self::suffix($row, 'downtime_class', ' · Downtime: ')
                .self::provisional($row, ' · **')
                .(($row['version_dependent'] ?? false) === true ? ' · **Depends on the server version, which was not established**' : '')
                .self::silenced($row, ' · **', '**'),
            '- '.self::text($row, 'documentation_url'),
            '',
        ];
    }

    /**
     * One rule, on one line — the same rule, said shorter.
     *
     * @param  array<array-key, mixed>  $row
     * @return list<string>
     */
    private static function compactRule(array $row): array
    {
        return [
            '- **'.self::text($row, 'id').'** (level '.self::text($row, 'level').')'
                .self::suffix($row, 'downtime_class', ', downtime ')
                .self::provisional($row, ', ')
                .(($row['version_dependent'] ?? false) === true ? ', version-dependent' : '')
                .self::silenced($row, ', **', '**')
                .' — '.self::text($row, 'documentation_url'),
        ];
    }

    /**
     * What the agent should do with this, and the one thing it must not conclude.
     *
     * The version caveat appears only when there is something it is about. A closing paragraph that
     * warns about version-dependent rules over a catalog that has none is filler, and filler is not
     * harmless here: every sentence a reader learns to skip makes the next one easier to skip too,
     * and one of them is the sentence that stops a bad migration.
     *
     * @param  bool  $hasVersionDependent  whether any rule could not be placed against a version
     * @return list<string>
     */
    private static function closing(bool $hasVersionDependent): array
    {
        return [
            '## Before you finish',
            '',
            'Run the linter rather than assuming this list is complete for your change: it describes '
                .'the rules, not your migration.'
                .($hasVersionDependent
                    ? ' A rule marked version-dependent could not be placed against a server version and may or may not apply.'
                    : ''),
            '',
        ];
    }

    /**
     * The entries grouped by category, each group keeping the snapshot's byte order.
     *
     * Grouped because a reader scanning for "is there a safety rule about this" wants them
     * together; ordered inside a group by the snapshot, so the file is as deterministic as its
     * source.
     *
     * @return array<string, list<array<array-key, mixed>>>
     */
    private static function byCategory(RuleCatalogSnapshot $snapshot): array
    {
        $grouped = [];

        foreach ($snapshot->entries as $row) {
            $grouped[self::text($row, 'category')][] = $row;
        }

        ksort($grouped, SORT_STRING);

        return $grouped;
    }

    /** @param  array<array-key, mixed>  $row */
    private static function text(array $row, string $key): string
    {
        $value = $row[$key] ?? '';

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * A ` · Label: value` fragment, or nothing when the field is absent.
     *
     * @param  array<array-key, mixed>  $row
     */
    private static function suffix(array $row, string $key, string $label): string
    {
        $value = self::text($row, $key);

        return $value === '' ? '' : $label.$value;
    }

    /**
     * The stability tier, said only when it is NOT `stable`.
     *
     * A rule this export carries is one the project's config selected, and a preview or experimental
     * rule only gets in when somebody opted into that tier. So the agent reading this needs the tier
     * for exactly one purpose: knowing which guidance is provisional and may change under it.
     *
     * Printed conditionally rather than on every rule, and that follows this file's own rule about
     * filler — a "stable" badge on the overwhelming majority is a word every reader learns to skip,
     * and one of the words next to it is the one that stops a bad migration. Silence here means
     * stable, which is also what the catalog means by it.
     *
     * The closing marker is passed in because the two renderers punctuate differently: the full form
     * bolds its fields, the compact one does not.
     *
     * @param  array<array-key, mixed>  $row
     */
    private static function provisional(array $row, string $prefix): string
    {
        $tier = self::text($row, 'stability');

        if ($tier === '' || $tier === 'stable') {
            return '';
        }

        return $prefix.$tier.(str_ends_with($prefix, '**') ? ' — this rule may change**' : ' — may change');
    }

    /**
     * How many of these rules each suite carries, as `audit 69 · lint 37`.
     *
     * The whole point of the line, and the finding that produced it: the catalog spans several
     * suites and no single command evaluates all of them. A consumer read one number as what its
     * gate checked — 102 against the 37 `sqlens:lint` actually ran — and believed the other 65
     * were being enforced by something.
     *
     * Counted from each row's own `suites`, so this cannot drift from what the engine filters on.
     * A rule in two suites is counted in both, which is why the caller says out loud that these do
     * not sum to the total — a reader who added them up and got more than the total would
     * reasonably conclude the numbers were wrong.
     *
     * Suite NAMES, not command names. Most map to a `sqlens:<name>` command and one does not:
     * `deploy` is reached through `sqlens:predeploy` and `sqlens:postdeploy`, so rendering a
     * command here would invent `sqlens:deploy` for every project that has a deploy rule.
     */
    private static function perSuite(RuleCatalogSnapshot $snapshot): string
    {
        $counts = [];

        foreach ($snapshot->entries as $row) {
            foreach (is_array($row['suites'] ?? null) ? $row['suites'] : [] as $suite) {
                if (is_string($suite) && $suite !== '') {
                    $counts[$suite] = ($counts[$suite] ?? 0) + 1;
                }
            }
        }

        // Byte order, like every other ordering in this chain: a locale-aware sort would put a
        // developer's machine and CI in disagreement about a file both of them generate.
        ksort($counts, SORT_STRING);

        $rendered = [];

        foreach ($counts as $suite => $count) {
            $rendered[] = $suite.' '.$count;
        }

        // An empty catalog has no suites to name, and "By suite:" followed by nothing reads as a
        // rendering fault rather than as an empty set.
        return $rendered === [] ? 'none' : implode(' · ', $rendered);
    }

    /**
     * The note that a rule cannot report under this configuration, or nothing when it can.
     *
     * Said on the rule's own line rather than in a list at the end, because the reader arrives here
     * by looking up one rule. A footnote about which rules are inert is a footnote nobody reaches
     * while writing the migration this file exists to prevent.
     *
     * @param  array<array-key, mixed>  $row
     */
    private static function silenced(array $row, string $prefix, string $suffix): string
    {
        $reason = $row['silenced_by_configuration'] ?? null;

        return is_string($reason) && $reason !== ''
            ? $prefix.'switched off by configuration: '.$reason.$suffix
            : '';
    }
}
