<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * The project's own composer.json, read for the single question an audit asks of it: which packages
 * did the project declare.
 *
 * ## Why the root is injected rather than fetched
 *
 * The obvious shape is `file_get_contents(base_path('composer.json'))` at the call site. `base_path()`
 * is a Foundation helper, and this package depends on focused `illuminate/*` components rather than
 * on the framework — the helper is not there to be called. An earlier version of the tenancy guard
 * reached for it anyway and the lean-dependency contract caught it. So the root arrives by
 * injection, from the one place that knows it: the container.
 *
 * ## An unreadable manifest is an empty one, and that is not a silent pass
 *
 * No file, an unreadable file, malformed JSON, no `require` block — all four answer the same way,
 * with no packages. This class answers "what did the project declare", and the absence of an answer
 * is not evidence for the opposite claim: nothing downstream concludes "therefore not multi-tenant".
 * The heuristic that consumes this still has its connection-shaped signals, and `mode: explicit`
 * remains available and is always honored. Refusing to audit a database because a JSON file could
 * not be parsed would trade a heuristic for an outage.
 */
final readonly class ProjectManifest
{
    public function __construct(private string $projectRoot) {}

    /**
     * Where the project is.
     *
     * Exposed because this class is already the one thing an audit run holds that knows the
     * answer, and a finding has to relativize its location against it. Injecting the same string
     * a second time into the same runner would be two sources for one fact, which is how they
     * come to disagree.
     */
    public function root(): string
    {
        return $this->projectRoot;
    }

    /**
     * The `require` block, exactly as the project wrote it.
     *
     * Typed `array<array-key, mixed>` rather than `array<string, string>`: it comes from a file this
     * package does not own, so a narrower annotation would be an assertion about somebody else's
     * JSON — and PHPStan would then remove the runtime checks that make it true.
     *
     * @return array<array-key, mixed>
     */
    public function requiredPackages(): array
    {
        $path = rtrim($this->projectRoot, '/').'/composer.json';

        // One branch, not two, and the docblock above is why: a missing file and an unreadable
        // one answer identically, so expressing the decision twice only made the second copy
        // unprovable. It needs a non-root user to reach — root reads a 000-mode file — so on a
        // container CI it went untested while looking covered on a developer's machine.
        $raw = is_file($path) ? @file_get_contents($path) : false;

        if ($raw === false) {
            return [];
        }

        $decoded = json_decode($raw, true);

        // `require-dev` is deliberately left out. A tenancy package a project pulls in to run its
        // own test suite does not shape the connection set an audit addresses, and reading it as a
        // declaration would ask a single-database project to name a reference tenant it has none of.
        return is_array($decoded) && is_array($require = $decoded['require'] ?? null)
            ? $require
            : [];
    }
}
