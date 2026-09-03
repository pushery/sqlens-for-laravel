<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * The unified diff `sqlens:format --diff` prints: what a write run WOULD change, in the one
 * notation every reviewer, editor and patch tool already reads.
 *
 * ## Why the package renders this itself
 *
 * The obvious library is `sebastian/diff`, and it is already on disk in every checkout — as a
 * transitive dependency of PHPUnit, which is `require-dev`. Reaching for it here would make a
 * shipped code path depend on a development dependency: green in this repository, fatal in a
 * consuming application that installed with `--no-dev`. The failure would land on the user, not
 * on us, and it would land at the moment they ran the command rather than at install time.
 *
 * Adding it to `require` instead is the other way, and this package's stance is written down:
 * SQLens ships into build pipelines and CI containers, where a dependency surface is a real cost.
 * A hundred lines that do exactly one job are cheaper than a dependency that does forty.
 *
 * ## The algorithm, and the bound on it
 *
 * Common prefix and suffix are trimmed first. That step alone does most of the work here, because
 * a formatter's output is the same content re-laid-out: the head and tail of a file are usually
 * untouched.
 *
 * What remains goes through a longest-common-subsequence table. That is O(n·m), which is fine for
 * the middle of a reformatted SQL file and is NOT fine for two files that share nothing. So the
 * refinement is bounded: past {@see self::MAX_REFINED_CELLS} the differing middle is emitted as
 * one coarse block — every old line removed, every new line added.
 *
 * That fallback is still a CORRECT unified diff. It is a less minimal one, which is a readability
 * cost and never a wrong answer — the distinction that matters, because this output is read by
 * people deciding whether to run the write.
 */
final class UnifiedDiff
{
    /**
     * Lines of unchanged context around each hunk. Three is what `diff -u` and every review tool
     * assume; a different number here would render diffs that look subtly wrong next to every
     * other diff the reader sees today.
     */
    private const int CONTEXT = 3;

    /**
     * The ceiling on the LCS table, in cells. 4 million is roughly a 2000×2000 middle — far past
     * any reformatted statement, and still bounded well below the point where the command would
     * appear to hang.
     */
    private const int MAX_REFINED_CELLS = 4_000_000;

    /**
     * The diff between two versions of one file, or an empty string when they are identical.
     *
     * An empty string rather than a header-only diff: the caller prints what it gets, and a
     * `--- / +++` pair over no hunks reads as "something changed here" to every eye that has ever
     * skimmed a patch.
     */
    public static function between(string $old, string $new, string $path): string
    {
        // NO `if ($old === $new) return ''` short-circuit, deliberately. Identical input already
        // flows to "no hunks" through the ordinary path — the common prefix consumes everything,
        // the middle is empty, and there is nothing to render. Special-casing it would buy no
        // speed worth having and would cost the thing that matters here: it would make the empty
        // result below unreachable, and an unreachable branch is one no test can cover and no
        // reader can trust.
        $hunks = self::hunks(self::lines($old), self::lines($new));

        if ($hunks === []) {
            return '';
        }

        // `a/` and `b/` because that is what `git apply` and `patch -p1` expect. A reader who wants
        // to apply this output should not have to rewrite the headers first.
        $out = '--- a/'.$path."\n+++ b/".$path."\n";

        foreach ($hunks as $hunk) {
            $out .= $hunk;
        }

        return $out;
    }

    /**
     * Split into lines that CARRY their own terminator: `["a\n", "b\n", "c"]`.
     *
     * That is the whole trick, and it exists for one case. The style rules include a final
     * newline, so "the formatter added the missing one" is a real change a `--diff` run must show
     * — and it is invisible to any splitter that throws terminators away, because the last line's
     * TEXT is identical on both sides. Keeping the terminator makes `"c"` and `"c\n"` unequal,
     * which is exactly what they are.
     *
     * @return list<string>
     */
    private static function lines(string $text): array
    {
        // ⚠️ NOTHING is normalized here, and an earlier draft of this class normalized CRLF to LF
        // "for comparison only". That was a silent green, measured: the pure-PHP core STRIPS the
        // CR — `select a\r\nfrom t\r\n` comes back as `SELECT a\nFROM t` — so a CRLF file really
        // is rewritten, and the normalizing draft printed no diff over a run that would change
        // every line of it. A diff that hides a change the write would make is worse than no diff.
        $parts = explode("\n", $text);
        $last = count($parts) - 1;
        $lines = [];

        foreach ($parts as $i => $part) {
            if ($i !== $last) {
                $lines[] = $part."\n";

                continue;
            }

            // A trailing newline TERMINATES the last line; it does not open an empty one. The empty
            // final segment `explode` hands back there is that terminator, already accounted for.
            if ($part !== '') {
                $lines[] = $part;
            }
        }

        return $lines;
    }

    /**
     * @param  list<string>  $before
     * @param  list<string>  $after
     * @return list<string>
     */
    private static function hunks(array $before, array $after): array
    {
        $head = self::commonPrefix($before, $after);

        $beforeTail = array_slice($before, $head);
        $afterTail = array_slice($after, $head);

        $tail = self::commonSuffix($beforeTail, $afterTail);

        $beforeMiddle = array_slice($beforeTail, 0, count($beforeTail) - $tail);
        $afterMiddle = array_slice($afterTail, 0, count($afterTail) - $tail);

        return self::render(self::script($beforeMiddle, $afterMiddle), $before, $head);
    }

    /**
     * @param  list<string>  $a
     * @param  list<string>  $b
     */
    private static function commonPrefix(array $a, array $b): int
    {
        $n = min(count($a), count($b));

        for ($i = 0; $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                return $i;
            }
        }

        return $n;
    }

    /**
     * @param  list<string>  $a
     * @param  list<string>  $b
     */
    private static function commonSuffix(array $a, array $b): int
    {
        $n = min(count($a), count($b));

        for ($i = 0; $i < $n; $i++) {
            if ($a[count($a) - 1 - $i] !== $b[count($b) - 1 - $i]) {
                return $i;
            }
        }

        return $n;
    }

    /**
     * The edit script over the differing middle, as a list of `[op, line]` with op in `-`, `+`, ` `.
     *
     * @param  list<string>  $a
     * @param  list<string>  $b
     * @return list<array{string, string}>
     */
    private static function script(array $a, array $b): array
    {
        if ($a === [] && $b === []) {
            return [];
        }

        if ($a === [] || $b === [] || count($a) * count($b) > self::MAX_REFINED_CELLS) {
            // The coarse block. Also the correct answer, not merely the cheap one, when one side is
            // empty: there is no common subsequence to find.
            $script = [];

            foreach ($a as $line) {
                $script[] = ['-', $line];
            }

            foreach ($b as $line) {
                $script[] = ['+', $line];
            }

            return $script;
        }

        return self::walk($a, $b, self::table($a, $b));
    }

    /**
     * Typed `array<int, array<int, int>>` rather than `list<list<int>>`: assigning into an
     * existing key keeps a list a list, and static analysis cannot see that. The narrower type is
     * unprovable AND unnecessary — {@see self::walk()} only ever looks a cell up by index.
     *
     * @param  list<string>  $a
     * @param  list<string>  $b
     * @return array<int, array<int, int>>
     */
    private static function table(array $a, array $b): array
    {
        $n = count($a);
        $m = count($b);

        $lcs = array_fill(0, $n + 1, array_fill(0, $m + 1, 0));

        for ($i = $n - 1; $i >= 0; $i--) {
            for ($j = $m - 1; $j >= 0; $j--) {
                $lcs[$i][$j] = $a[$i] === $b[$j]
                    ? $lcs[$i + 1][$j + 1] + 1
                    : max($lcs[$i + 1][$j], $lcs[$i][$j + 1]);
            }
        }

        return $lcs;
    }

    /**
     * @param  list<string>  $a
     * @param  list<string>  $b
     * @param  array<int, array<int, int>>  $lcs
     * @return list<array{string, string}>
     */
    private static function walk(array $a, array $b, array $lcs): array
    {
        $script = [];
        $i = 0;
        $j = 0;
        $n = count($a);
        $m = count($b);

        while ($i < $n && $j < $m) {
            if ($a[$i] === $b[$j]) {
                $script[] = [' ', $a[$i]];
                $i++;
                $j++;

                continue;
            }

            // The tie goes to the DELETION, deliberately and consistently. Either choice yields a
            // minimal script; picking the same one every time is what makes the rendered diff
            // deterministic, which this package treats as a survival condition rather than a nicety.
            if ($lcs[$i + 1][$j] >= $lcs[$i][$j + 1]) {
                $script[] = ['-', $a[$i]];
                $i++;

                continue;
            }

            $script[] = ['+', $b[$j]];
            $j++;
        }

        while ($i < $n) {
            $script[] = ['-', $a[$i]];
            $i++;
        }

        while ($j < $m) {
            $script[] = ['+', $b[$j]];
            $j++;
        }

        return $script;
    }

    /**
     * Group the edit script into hunks with context, and render each with its `@@` header.
     *
     * @param  list<array{string, string}>  $script
     * @param  list<string>  $before
     * @return list<string>
     */
    private static function render(array $script, array $before, int $head): array
    {
        // The script covers the middle only; the head is unchanged context that both sides share,
        // so the full picture is: head context, script, tail context.
        $full = [];

        for ($i = 0; $i < $head; $i++) {
            $full[] = [' ', $before[$i]];
        }

        foreach ($script as $entry) {
            $full[] = $entry;
        }

        $tailStart = $head + self::consumed($script, '-');
        $tailEnd = count($before);

        for ($i = $tailStart; $i < $tailEnd; $i++) {
            $full[] = [' ', $before[$i]];
        }

        return self::group($full);
    }

    /**
     * How many lines of one side the script consumed.
     *
     * @param  list<array{string, string}>  $script
     */
    private static function consumed(array $script, string $side): int
    {
        $n = 0;

        foreach ($script as [$op]) {
            if ($op === $side || $op === ' ') {
                $n++;
            }
        }

        return $n;
    }

    /**
     * @param  list<array{string, string}>  $full
     * @return list<string>
     */
    private static function group(array $full): array
    {
        $changed = [];

        foreach ($full as $index => [$op]) {
            if ($op !== ' ') {
                $changed[] = $index;
            }
        }

        if ($changed === []) {
            return [];
        }

        $last = count($full) - 1;
        $hunks = [];

        // Seeded from the FIRST change rather than from null. The nullable version needed a
        // "did we start one yet" test that, after the guard above, can only ever answer yes.
        $start = max(0, $changed[0] - self::CONTEXT);
        $end = min($last, $changed[0] + self::CONTEXT);

        foreach (array_slice($changed, 1) as $index) {
            $from = max(0, $index - self::CONTEXT);
            $to = min($last, $index + self::CONTEXT);

            // Overlapping context windows become ONE hunk. Two hunks whose context touches would
            // print the same lines twice, and a patch tool would reject the second one.
            if ($from <= $end + 1) {
                $end = max($end, $to);

                continue;
            }

            $hunks[] = self::hunk($full, $start, $end);
            $start = $from;
            $end = $to;
        }

        $hunks[] = self::hunk($full, $start, $end);

        return $hunks;
    }

    /**
     * @param  list<array{string, string}>  $full
     */
    private static function hunk(array $full, int $start, int $end): string
    {
        $oldStart = 1;
        $newStart = 1;

        for ($i = 0; $i < $start; $i++) {
            if ($full[$i][0] !== '+') {
                $oldStart++;
            }

            if ($full[$i][0] !== '-') {
                $newStart++;
            }
        }

        $oldCount = 0;
        $newCount = 0;
        $body = '';

        for ($i = $start; $i <= $end; $i++) {
            [$op, $line] = $full[$i];

            if ($op !== '+') {
                $oldCount++;
            }

            if ($op !== '-') {
                $newCount++;
            }

            // The terminator lives IN the line, so it is stripped for display and its absence is
            // reported the way every diff tool reports it. Without this marker a reader could not
            // tell "the last line changed" from "the last line gained its final newline".
            $body .= $op.rtrim($line, "\n")."\n";

            if (! str_ends_with($line, "\n")) {
                $body .= "\\ No newline at end of file\n";
            }
        }

        return '@@ -'.self::span($oldStart, $oldCount).' +'.self::span($newStart, $newCount)." @@\n".$body;
    }

    /**
     * One side of an `@@` header, in the two spellings `diff -u` actually uses.
     *
     * Both special cases were measured against it rather than reasoned about, because each is
     * invisible until something tries to APPLY the output:
     *
     *   - a length of ONE omits the count entirely — `+1`, never `+1,1`;
     *   - a length of ZERO names the line it comes AFTER, which over an empty side is line 0.
     */
    private static function span(int $start, int $count): string
    {
        if ($count === 1) {
            return (string) $start;
        }

        return ($count === 0 ? $start - 1 : $start).','.$count;
    }
}
