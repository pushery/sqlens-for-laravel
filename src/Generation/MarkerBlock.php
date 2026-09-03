<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

/**
 * The two lines that bound a generated region inside a file the project owns.
 *
 * ## Why the opening marker is matched by a PREFIX
 *
 * The opening line carries the generator version and the snapshot hash, so a reader can see at a
 * glance which catalog produced the block below it. That means the line CHANGES whenever the
 * catalog does — and a writer that looked for the exact line it was about to write would fail to
 * find the previous one the moment anything moved. It would then append a second block beside the
 * stale first, and the file would grow one block per regeneration.
 *
 * So the identity of an opening marker is its stable PREFIX, and the version and hash ride behind
 * it. Finding a stale marker is the normal case, not an error case.
 *
 * ## No timestamp
 *
 * Deliberately. The hash already says whether anything changed; a timestamp would make every run
 * produce a diff, which trains everyone to stop reading the diff.
 */
final readonly class MarkerBlock
{
    /**
     * @param  string  $openPrefix  the stable text an opening marker line begins with
     * @param  string  $openLine  the full opening line to WRITE, prefix included
     * @param  string  $closeLine  the closing line, carrying nothing that can go stale
     */
    private function __construct(
        public string $openPrefix,
        public string $openLine,
        public string $closeLine,
    ) {}

    /**
     * A marker pair for one target format.
     *
     * The syntax comes from the caller rather than from here: an HTML comment suits markdown, a
     * `#` line suits a rules file, and a class that knew which was which would be a second place
     * deciding what each format looks like.
     *
     * @param  string  $openPrefix  e.g. `<!-- sqlens:agent-rules:begin`
     * @param  string  $openSuffix  what closes the opening line, e.g. ` -->`
     */
    public static function of(string $openPrefix, string $openSuffix, string $closeLine, string $generatorVersion, string $snapshotHash): self
    {
        return new self(
            $openPrefix,
            $openPrefix.' v'.$generatorVersion.' catalog='.$snapshotHash.$openSuffix,
            $closeLine,
        );
    }

    /**
     * The agent-rules marker pair, in the HTML-comment form the Claude target needs.
     *
     * Here rather than only behind {@see AgentContextFormat::markers()} because the format accessor
     * is nullable — two of the three formats own their whole file and have no region — and a caller
     * that KNOWS it writes a region would otherwise have to defend against a null that cannot
     * happen. A defense against an impossible state is a branch no test can reach.
     */
    public static function agentRules(string $generatorVersion, string $snapshotHash): self
    {
        return self::of(
            '<!-- sqlens:agent-rules:begin',
            ' -->',
            '<!-- sqlens:agent-rules:end -->',
            $generatorVersion,
            $snapshotHash,
        );
    }

    /** Whether a line opens the region — by prefix, so a stale version or hash still matches. */
    public function opens(string $line): bool
    {
        return str_starts_with(trim($line), $this->openPrefix);
    }

    /** Whether a line closes the region. Exact, because nothing on it can go stale. */
    public function closes(string $line): bool
    {
        return trim($line) === trim($this->closeLine);
    }
}
