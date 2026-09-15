<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use PhpParser\NodeTraverser;
use Pushery\SQLens\Capture\PreScan\MigrationFileScanner;
use Pushery\SQLens\Capture\PreScan\ScannedMigration;
use Pushery\SQLens\Capture\PreScan\SchemaSubjectCollector;

/**
 * Which migration introduced a catalog subject — the anchor an audit finding has no other way to get.
 *
 * ## Built from the migrations, never from the database
 *
 * The catalog knows `public.orders.customer_id`; the migration knows `orders` and `customer_id`.
 * Joining them is a matter of reading the files, and this reads them the way the rest of the package
 * does: {@see MigrationFileScanner} parses each file once and never
 * includes it. Nothing here runs a migration, and nothing here touches a connection.
 *
 * ## Every failure is an ABSENT anchor, never a wrong one
 *
 * A file that will not parse, a table name that is a variable, a subject no migration mentions — all
 * three answer null, and the finding is reported without a file and line exactly as it was before.
 * That asymmetry is deliberate: a missing anchor costs a reader one search, and a wrong one sends
 * them to edit a file that had nothing to do with the finding.
 *
 * ## The schema qualifier is stripped, in one place
 *
 * A catalog subject is `public.orders`; a migration says `orders`. The map strips the leading
 * qualifier when a lookup fails with it, and only then — so a table genuinely called `public.orders`
 * inside a migration still matches itself first.
 *
 * ## After `schema:dump --prune` there is nothing to read
 *
 * An application that squashed its migrations has no files left to anchor to, and those are
 * disproportionately the long-lived ones with the most findings. The map answers null for every
 * subject there, which is honest and is what the documentation says.
 */
final class MigrationSubjectMap
{
    /** @var array<string, MigrationAnchor>|null */
    private ?array $anchors = null;

    /** @param list<string> $paths absolute migration directories, in the order they should be read */
    public function __construct(private readonly array $paths) {}

    /**
     * The map for a project, from the directory Laravel migrates from by default.
     *
     * One path, not a resolved set, and that is a deliberate floor rather than an oversight: the
     * full resolution needs the application's migrator, which a rule does not have and should not
     * acquire — a rule that reached for the container would stop being answerable from a bare
     * project root. A package that registered its own migration path simply yields no anchor for
     * its tables, which is the same ordinary absence as a squashed schema, and reported the same
     * way: without a file and a line.
     */
    public static function forProjectRoot(string $projectRoot): self
    {
        return new self([rtrim($projectRoot, '/').'/database/migrations']);
    }

    /** The migration that introduced this subject, or null — and null is an ordinary answer. */
    public function anchorFor(string $qualifiedName): ?MigrationAnchor
    {
        $anchors = $this->anchors();

        if (isset($anchors[$qualifiedName])) {
            return $anchors[$qualifiedName];
        }

        // Only now the unqualified form. Trying it first would let `public.orders` match a table a
        // migration really named `orders` while a differently-schema'd one of the same name exists.
        $bare = $this->withoutSchema($qualifiedName);

        return $bare === null ? null : ($anchors[$bare] ?? null);
    }

    /** How many subjects the scan resolved — zero is a complete answer, and the docs say when. */
    public function size(): int
    {
        return count($this->anchors());
    }

    /** @return array<string, MigrationAnchor> */
    private function anchors(): array
    {
        if ($this->anchors !== null) {
            return $this->anchors;
        }

        $scanner = new MigrationFileScanner;
        $anchors = [];

        foreach ($this->files() as $file) {
            $scanned = $scanner->scan($file);

            // A ScanFailure is not an error here. The pre-scan treats an unparseable migration as a
            // reason to refuse a capture; this map has no such stake — it simply has nothing to say
            // about that file, and says nothing.
            if (! $scanned instanceof ScannedMigration) {
                continue;
            }

            $collector = new SchemaSubjectCollector($file);
            $traverser = new NodeTraverser;
            $traverser->addVisitor($collector);
            $traverser->traverse($scanned->ast);

            foreach ($collector->subjects() as $subject => $where) {
                $anchors[$subject] ??= MigrationAnchor::at($where['file'], $where['line']);
            }
        }

        return $this->anchors = $anchors;
    }

    /** @return list<string> every migration file, in name order, which for a timestamped set is chronological */
    private function files(): array
    {
        $files = [];

        foreach ($this->paths as $path) {
            if (! is_dir($path)) {
                continue;
            }

            foreach (glob(rtrim($path, '/').'/*.php') ?: [] as $file) {
                $files[] = $file;
            }
        }

        sort($files, SORT_STRING);

        return $files;
    }

    /** `public.orders` becomes `orders`; a name with no qualifier becomes null rather than itself. */
    private function withoutSchema(string $qualifiedName): ?string
    {
        $dot = strpos($qualifiedName, '.');

        return $dot === false ? null : substr($qualifiedName, $dot + 1);
    }
}
