<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Error;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver as ParserNameResolver;
use PhpParser\ParserFactory;

/**
 * Reads a migration file as TEXT and parses it — it never runs it.
 *
 * No `include`, no `eval`, no instantiation of the migration class. That is not
 * a performance choice: loading a migration to inspect it would execute its
 * top-level code, and the whole point of the pre-scan is to find out whether
 * running this file is safe BEFORE anything of it runs. A scanner that had to
 * run the file first could not answer its own question.
 *
 * The file is parsed exactly once and the resolved call list is shared with every
 * detector.
 */
final class MigrationFileScanner
{
    /**
     * How many times any scanner has invoked the PHP parser this process.
     *
     * The pre-scan's whole cost model rests on parsing each file ONCE and sharing
     * the result with every detector — a per-detector parse would multiply the
     * scan's cost by the number of patterns, and the scan sits in front of the
     * sub-second fast path. That "once, not once per detector" is a promise a
     * comment cannot keep, so this counter lets a performance test assert it:
     * over N files it must read exactly N, never N × detectors. It counts only
     * parses that actually reached the parser, so an unreadable file (which never
     * parses) does not inflate it.
     */
    private static int $parseCount = 0;

    public function __construct(private readonly NameResolver $resolver = new NameResolver) {}

    /** The number of parser invocations so far — the pre-scan's parse budget meter. */
    public static function parseCount(): int
    {
        return self::$parseCount;
    }

    /** Reset the parse counter — for a test that measures a single run in isolation. */
    public static function resetParseCount(): void
    {
        self::$parseCount = 0;
    }

    /**
     * Parse one migration file.
     *
     * A file that cannot be read or parsed comes back as a `ScanFailure`, never
     * as an empty hit list: "I could not look" and "I looked and found nothing"
     * are different answers, and only one of them may be reported as clean.
     */
    public function scan(string $file): ScannedMigration|ScanFailure
    {
        // ONE read, ONE error path. Splitting "does not exist" from "exists but
        // could not be read" would add a second arm only a filesystem race can
        // reach — untestable by construction, and an untested arm inside a guard
        // is exactly where guards rot. The warning is suppressed because turning
        // it into a named three-valued result IS this method's job.
        $source = @file_get_contents($file);

        if ($source === false) {
            return ScanFailure::unparsable($file, 'The migration file could not be read.');
        }

        try {
            self::$parseCount++;

            // `?? []` because the parser's signature allows null when a non-throwing
            // error handler swallows a fatal; this scanner uses the throwing default.
            $ast = new ParserFactory()->createForHostVersion()->parse($source) ?? [];
        } catch (Error $error) {
            return ScanFailure::unparsable($file, 'The migration file is not valid PHP: '.$error->getRawMessage());
        }

        if ($ast === []) {
            return ScanFailure::unparsable($file, 'The migration file produced no parseable statements.');
        }

        // Two traversals, one parse. Name resolution has to finish COMPLETELY
        // before calls are read: a receiver like `(new UserBackfill)->run()` has
        // its class name in a CHILD node, which a single interleaved pass would
        // still be unresolved when the enclosing call is inspected — silently
        // yielding the short name and letting an imported class look unresolved.
        $resolved = new NodeTraverser(new ParserNameResolver)->traverse($ast);

        $collector = new CallCollector($this->resolver);
        new NodeTraverser($collector)->traverse($resolved);

        return new ScannedMigration($file, array_values($resolved), $collector->calls());
    }
}
