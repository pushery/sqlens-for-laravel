<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * How formatted SQL should look — the whole of what a project gets to decide.
 *
 * ## Why the options are few, and stay few
 *
 * Every option is a decision two people on a team will disagree about forever, and a formatter's
 * value comes from ending that argument rather than parameterizing it. These four are the ones that
 * change what a diff looks like on a real migration; everything else a formatter could expose makes
 * two projects' output differ without making either one clearer.
 *
 * ## The fingerprint is why this class exists at all
 *
 * A formatted statement is only reproducible if the settings that produced it are known. Two runs
 * that disagree are a defect; two runs under different styles that disagree are not, and nothing but
 * a recorded fingerprint separates those cases. It travels in every {@see FormatResult}.
 */
final readonly class FormatStyle
{
    public function __construct(
        /** Spaces per indentation level. */
        public int $indent = 4,
        /** Whether keywords are upper-cased. */
        public bool $uppercaseKeywords = true,
        /**
         * Where a comma sits when a list breaks across lines.
         *
         * The one option here that is purely aesthetic, and it is present because it is the one
         * people actually argue about: leading commas make a git diff of an added column one line
         * instead of two.
         */
        public bool $leadingCommas = false,
        /** The column past which a single-line statement is broken up. */
        public int $lineWidth = 100,
    ) {}

    /**
     * A short, stable digest of these settings.
     *
     * Short because it appears in every result and every report line; stable because a run that
     * cannot say which style produced its output cannot claim the output is reproducible.
     *
     * Built from the values rather than from `serialize()`: a serialized object carries the class
     * NAME, so renaming this class would change every fingerprint ever recorded without changing a
     * single setting.
     */
    public function fingerprint(): string
    {
        return substr(hash('xxh128', implode('|', [
            $this->indent,
            $this->uppercaseKeywords ? '1' : '0',
            $this->leadingCommas ? '1' : '0',
            $this->lineWidth,
        ])), 0, 12);
    }
}
