<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * Whether a file lives inside the dependency tree — asked in ONE place, because two places would
 * disagree.
 *
 * Two layers need the answer and they reach it from different strings. The capture layer classifies
 * an already-resolved path when it decides whether a statement came from a migration of yours; the
 * lint layer asks about the raw path the migrator handed it, before anything has resolved it. Both
 * are "is this vendor code", and answering them separately is how one of them ends up wrong without
 * anything going red.
 *
 * ## Why the RESOLUTION belongs in here, and not just the predicate
 *
 * Sharing only the segment match is the trap, and it is measurable rather than theoretical. A
 * Composer `path` repository symlinks `vendor/<vendor>/<package>` at a directory outside the tree,
 * and the two strings then answer differently:
 *
 *     raw       …/app/vendor/pkg/migrations/0001_x.php   ->  vendor
 *     realpath  …/local/migrations/0001_x.php            ->  NOT vendor
 *
 * A caller matching the raw path would drop the file from the enumeration while the capture layer,
 * matching the resolved one, would bind the same file as a migration of yours. Two opposite answers
 * out of one "shared" predicate — and a guard grepping for the string `vendor` reads both call
 * sites as consistent.
 *
 * So the resolution happens here, and the answer is about where the file REALLY is. A symlinked
 * package is a local checkout you are working on: code you can change, which is the whole
 * distinction the vendor switch draws.
 *
 * ## The segment, not the substring
 *
 * Matched as a path SEGMENT: a project directory called `app/Vendors/` or a migration named
 * `2026_01_01_add_vendor_id.php` contains the word and is not the dependency tree, and treating
 * either as vendor code would silence a real finding in a project's own migrations.
 */
final readonly class VendorPath
{
    /**
     * Whether $path resolves to a file inside a `vendor/` directory.
     *
     * A path that does not exist answers FALSE rather than guessing from its spelling. The two
     * cases that reach here are a file deleted between resolution and judgment and a synthetic path
     * built by a test or a tool, and neither is evidence that something is vendor code — while
     * answering true would drop it from a run silently, which is the direction that costs a finding.
     */
    public static function contains(string $path): bool
    {
        $resolved = realpath($path);

        if ($resolved === false) {
            return false;
        }

        $separator = DIRECTORY_SEPARATOR;

        return str_contains($resolved, $separator.'vendor'.$separator);
    }
}
