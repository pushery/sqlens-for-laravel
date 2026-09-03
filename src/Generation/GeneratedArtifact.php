<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Pushery\SQLens\Reporting\Agent\Redactor;

/**
 * One file a renderer produced — as a VALUE, never as a side effect.
 *
 * This object is the whole reason `--check` and writing can be one code path. The exporter hands
 * back a list of these; the command either writes them or compares them to what is on disk, and
 * the branch sits at the very end. Two code paths for "fast" and "correct" are forbidden here for
 * the same reason they are forbidden in the engine — they agree until they do not, and the
 * disagreement is discovered by a user.
 *
 * ## The marker bounds
 *
 * Some targets are files the tool does not own. A project's `CLAUDE.md` holds the project's own
 * prose, and a regeneration must replace only ITS section. So an artifact may carry the two marker
 * lines that bound the region it is responsible for; an artifact without them owns its whole file.
 *
 * Both or neither. A start with no end has no region — the writer would have to guess where the
 * section stops, and guessing there means eating somebody's documentation.
 *
 * ## The snapshot hash
 *
 * Carried so a written file can say which catalog produced it. That is what lets `--check` answer
 * "this file is stale" rather than only "this file differs", and it is why the hash covers the
 * catalog's context as well as its rules.
 */
final readonly class GeneratedArtifact
{
    /**
     * @param  string  $path  repo-relative; the command resolves it against the project root
     * @param  string  $markerStart  the opening marker line, or '' when the artifact owns the file
     * @param  string  $markerEnd  the closing marker line, or '' likewise
     */
    private function __construct(
        public string $path,
        public string $content,
        public ArtifactFamily $family,
        public string $snapshotHash,
        public string $markerStart,
        public string $markerEnd,
    ) {}

    /** An artifact that owns its whole file — the file exists because this renderer writes it. */
    public static function wholeFile(string $path, string $content, ArtifactFamily $family, string $snapshotHash): self
    {
        return new self($path, ArtifactWriting::normalize($content), $family, $snapshotHash, '', '');
    }

    /**
     * An artifact that owns a marked REGION of a file somebody else also writes in.
     *
     * The content is normalized the same way either shape: the line endings and the trailing
     * newline are properties of the format, and a region that used different ones would make the
     * host file inconsistent with itself.
     */
    public static function markedRegion(
        string $path,
        string $content,
        ArtifactFamily $family,
        string $snapshotHash,
        string $markerStart,
        string $markerEnd,
    ): self {
        return new self($path, ArtifactWriting::normalize($content), $family, $snapshotHash, $markerStart, $markerEnd);
    }

    /**
     * The same artifact with its content masked.
     *
     * A new value rather than a mutation, and the path stays untouched: a redactor is about what a
     * file SAYS, never about where it goes. A version that could move an artifact would be a second
     * thing deciding a destination.
     */
    public function redactedWith(Redactor $redactor): self
    {
        return new self(
            $this->path,
            $redactor->in($this->content),
            $this->family,
            $this->snapshotHash,
            $this->markerStart,
            $this->markerEnd,
        );
    }

    /** Whether this artifact replaces a region rather than a whole file. */
    public function isMarkedRegion(): bool
    {
        return $this->markerStart !== '' && $this->markerEnd !== '';
    }
}
