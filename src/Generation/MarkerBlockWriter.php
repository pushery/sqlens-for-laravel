<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

/**
 * Replacing a generated region inside a file the PROJECT owns — once, with one owner.
 *
 * Two renderers need this: a section in a project's own agent instructions, and the same shape in
 * a second tool's file. Two implementations of one piece of text manipulation do not maybe drift;
 * they drift, and the second copy is always the less tested one.
 *
 * ## The rule the whole class is arranged around
 *
 * What the project wrote belongs to the project. This writer touches its own block and nothing
 * else — every other line comes back byte for byte, blank lines and all. That is why the
 * normalization below removes each block INDIVIDUALLY rather than spanning from the first opening
 * marker to the last closing one: two generated blocks with somebody's own paragraph between them
 * is a real state, and spanning would eat the paragraph.
 *
 * ## The seven states, and what each becomes
 *
 * | State | Result |
 * |---|---|
 * | no file at all | the block, alone |
 * | file, no block | the block appended, one blank line after the existing text |
 * | one block | replaced in place |
 * | two or more blocks | ALL removed, one written back where the first began |
 * | nested blocks | the outer region removed whole; one block written back |
 * | an opening marker with no closing one | the stray line removed; one block written back there |
 * | a closing marker with no opening one | the same |
 *
 * A stale version or hash on the opening line is not one of these states. It is the ORDINARY case,
 * and it is why {@see MarkerBlock} matches an opening line by prefix.
 *
 * ## It does not write
 *
 * It returns the complete new file content. Writing belongs to the command, which is what lets
 * `--check` ask this same object whether anything would change instead of running a second
 * comparison that agrees until it does not.
 */
final readonly class MarkerBlockWriter
{
    /**
     * The complete new content of the file.
     *
     * @param  string|null  $existing  the current file content, or null when the file does not exist
     * @param  string  $block  the generated body, WITHOUT the marker lines
     */
    public function apply(?string $existing, MarkerBlock $marker, string $block): string
    {
        $rendered = $this->render($marker, $block);

        if ($existing === null || trim($existing) === '') {
            return ArtifactWriting::normalize($rendered);
        }

        $lines = explode("\n", str_replace(["\r\n", "\r"], "\n", $existing));
        $removed = $this->regions($lines, $marker);

        if ($removed === []) {
            // Appended with one blank line between, because a generated block butting straight up
            // against somebody's last paragraph reads as part of it.
            return ArtifactWriting::normalize(rtrim($existing, "\n")."\n\n".$rendered);
        }

        $insertAt = min($removed);
        $kept = [];

        foreach ($lines as $index => $line) {
            if ($index === $insertAt) {
                $kept[] = $rendered;
            }

            if (! in_array($index, $removed, true)) {
                $kept[] = $line;
            }
        }

        return ArtifactWriting::normalize(implode("\n", $kept));
    }

    /**
     * Whether applying would change the file — asked of the same call that would do it.
     *
     * Not a comparison of its own. `--check` and writing differ in whether the result reaches the
     * disk and in nothing else, so there is no second path here to disagree with the first.
     */
    public function wouldChange(?string $existing, MarkerBlock $marker, string $block): bool
    {
        return $this->apply($existing, $marker, $block) !== $existing;
    }

    /** The block with its markers, as it appears in the file. */
    private function render(MarkerBlock $marker, string $block): string
    {
        return $marker->openLine."\n".trim($block, "\n")."\n".$marker->closeLine;
    }

    /**
     * Every line index belonging to a generated region — complete blocks and stray markers alike.
     *
     * Each opening marker is paired with the NEXT closing one after it, and lines in between are
     * claimed. A second opening marker inside an unclosed region is part of that region rather than
     * the start of a new one, which is what collapses nesting without a special case.
     *
     * An opening marker with no closing one after it claims only ITSELF. Claiming to the end of the
     * file would be the obvious reading and the destructive one: everything a project wrote below a
     * corrupted marker would disappear, and the file would look tidy afterwards.
     *
     * @param  list<string>  $lines
     * @return list<int>
     */
    private function regions(array $lines, MarkerBlock $marker): array
    {
        $claimed = [];
        $open = null;

        foreach ($lines as $index => $line) {
            if ($open === null && $marker->opens($line)) {
                $open = $index;

                continue;
            }

            if ($open !== null && $marker->closes($line)) {
                for ($i = $open; $i <= $index; $i++) {
                    $claimed[] = $i;
                }

                $open = null;
            }
        }

        // An unclosed region at the end of the file: only the stray marker line goes.
        if ($open !== null) {
            $claimed[] = $open;
        }

        // Closing markers nothing opened. They are debris from a hand-edit, and leaving one behind
        // would make the next run find a region that starts nowhere.
        foreach ($lines as $index => $line) {
            if (! in_array($index, $claimed, true) && $marker->closes($line)) {
                $claimed[] = $index;
            }
        }

        sort($claimed);

        return $claimed;
    }
}
