<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

/**
 * A YAML frontmatter block, written once for the two formats that carry one.
 *
 * Deliberately NOT a YAML library. What goes in here is a fixed, tiny set of keys with string and
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
     * @param  array<string, string|bool>  $fields  in the order they should appear
     */
    public static function render(array $fields): string
    {
        if ($fields === []) {
            return '';
        }

        $lines = ['---'];

        foreach ($fields as $key => $value) {
            $lines[] = $key.': '.(is_bool($value) ? ($value ? 'true' : 'false') : '"'.str_replace('"', '\"', $value).'"');
        }

        return implode("\n", [...$lines, '---', '']);
    }
}
