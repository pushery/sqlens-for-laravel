<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

/**
 * A YAML frontmatter block, written once for the two formats that carry one.
 *
 * Deliberately not a YAML library. What goes in here is a fixed, tiny set of keys with string and
 * boolean values, decided by {@see AgentContextFormat} from three vendors' documented field lists —
 * so the failure a serializer would protect against (arbitrary nested data, unquoted specials)
 * cannot arise, and a dependency that could reorder keys or reflow values would be a determinism
 * risk taken for no benefit.
 *
 * Strings are quoted unconditionally. A glob starts with `*` often enough that leaving quoting to a
 * heuristic means the heuristic is the thing that breaks, once, in whichever file nobody opened.
 */
final readonly class Frontmatter
{
    /**
     * The block, delimiters included — or an empty string when there are no fields.
     *
     * Empty rather than an empty block, because `---\n---` at the top of a file is a document
     * header that says nothing, and the one format with no frontmatter is a SECTION inside somebody
     * else's file, where a header would be text in the middle of their document.
     *
     * A list renders as a YAML sequence, one quoted item per line, as the `paths:` key of a rules file wants it.
     *
     * @param  array<string, string|bool|list<string>>  $fields  in the order they should appear
     */
    public static function render(array $fields): string
    {
        if ($fields === []) {
            return '';
        }

        $lines = ['---'];

        foreach ($fields as $key => $value) {
            if (is_array($value)) {
                $lines[] = $key.':';

                foreach ($value as $item) {
                    $lines[] = '  - '.self::quoted($item);
                }

                continue;
            }

            $lines[] = $key.': '.(is_bool($value) ? ($value ? 'true' : 'false') : self::quoted($value));
        }

        return implode("\n", [...$lines, '---', '']);
    }

    private static function quoted(string $value): string
    {
        return '"'.str_replace('"', '\"', $value).'"';
    }
}
