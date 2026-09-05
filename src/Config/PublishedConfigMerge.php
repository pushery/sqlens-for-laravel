<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * How a published `config/sqlens.php` combines with the one this package ships.
 *
 * ## What Laravel's own two helpers do, and why neither is right here
 *
 * `mergeConfigFrom()` is a flat `array_merge`: it asks ONE question per top-level key. A project
 * that sets a nested value has to hand over the whole block it lives in — and that block then never
 * receives a newly shipped key again. With a 99 KB reference configuration that is not a corner:
 * answering `security.rls.mode` means either publishing all 99 KB or freezing the entire `security`
 * block. Measured in a consuming project: a minimal file setting `security.runtime_connection`
 * resolved `security.rls.mode` to null, a key the package ships a default for.
 *
 * `replaceConfigRecursivelyFrom()` is `array_replace_recursive`, and it trades that defect for a
 * quieter one. It replaces LISTS BY INDEX:
 *
 *     package  ['database/schema/*']   published  []        =>  ['database/schema/*']
 *     package  ['a', 'b', 'c']         published  ['x']     =>  ['x', 'b', 'c']
 *
 * So emptying a list does nothing and shortening one keeps the package's tail. That is not
 * hypothetical either: `format.exclude` ships with an entry, and this package's own
 * configuration comment tells a project that hand-maintains its schema file to EMPTY it.
 *
 * ## The rule, in one sentence
 *
 * The PACKAGE's default decides. Where it is a map, recurse; where it is anything else — a list, a
 * scalar, null — the published value wins whole, including when it is an empty list, which is the
 * answer neither of Laravel's helpers can express.
 *
 * ⚠️ The deciding side is the package's, and reading it off the PUBLISHED side instead is a real
 * defect that a control arm caught before this shipped. An empty array in a published file means two
 * different things depending on where it sits: `'format' => []` is a project saying it sets nothing
 * in that block, while `'exclude' => []` is a project saying none. They are indistinguishable
 * from the published side and obvious from the package's, because the package ships a map at the
 * first and a list at the second.
 */
final readonly class PublishedConfigMerge
{
    /**
     * The effective configuration: the package's defaults, overridden by what the project published.
     *
     * @param  array<array-key, mixed>  $package
     * @param  array<array-key, mixed>  $published
     * @return array<array-key, mixed>
     */
    public static function of(array $package, array $published): array
    {
        foreach ($published as $key => $value) {
            $default = $package[$key] ?? null;

            // Recurse only where the PACKAGE ships a map, and only where the published value is one
            // too — or empty, which over a map means "I set nothing in this block" and yields the
            // defaults unchanged. A published map over a package LIST is a shape change and replaces:
            // merging across one would produce a value neither side wrote.
            $package[$key] = is_array($value) && is_array($default) && self::isMap($default) && ($value === [] || self::isMap($value))
                ? self::of($default, $value)
                : $value;
        }

        return $package;
    }

    /**
     * Is this array a MAP — named keys — rather than a list?
     *
     * An empty array answers FALSE, and the caller is what makes that safe: it asks this about the
     * package's default, where empty means the package ships no entries and a published value can
     * only be replacing them.
     *
     * @param  array<array-key, mixed>  $value
     */
    private static function isMap(array $value): bool
    {
        return $value !== [] && ! array_is_list($value);
    }
}
