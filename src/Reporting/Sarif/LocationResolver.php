<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Sarif;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Where a finding IS, in the two answers SARIF has for it — and why most of this package's findings
 * need the second one.
 *
 * A migration or callsite finding has a file and a line, and that is the easy half. Everything the
 * audit and the security suite produce is about a live database: a table, a role, a grant, a server
 * variable. None of those is anywhere in the repository, and SARIF's physical location is the only
 * thing GitHub's code-scanning tab can attach an alert to.
 *
 * ## The two ways to get this wrong, and they are opposite
 *
 * **Emit nothing.** SARIF accepts an empty `locations` array and the document validates. GitHub then
 * pins the alert to the repository root, which reads as *line 1 of nothing in particular* — and the
 * subject, the thing the finding is actually about, is nowhere a machine can read it.
 *
 * **Invent a position.** Anchoring to some file and a line makes the alert look like a finding about
 * that code. A reader opens it, sees an unrelated statement, and learns not to trust the tab.
 *
 * ## What this does instead
 *
 * Both halves of SARIF's own answer, which exists precisely for this:
 *
 * - `logicalLocations` carries the REAL subject as a `fullyQualifiedName` — `pgsql.public.orders` —
 *   so the object identity is machine-readable and stable across runs and machines.
 * - `physicalLocation` carries an ANCHOR. Where the migration that introduced the subject could be
 *   read, that is the anchor, with its real line: the alert then lands in the diff somebody is
 *   already looking at. Where it could not — a table named by a variable, an unparseable file, an
 *   application that has run `schema:dump --prune` — the anchor is one configurable repository
 *   file, `config/sqlens.php` by default, chosen because it is the file a reader would edit in
 *   response, and it carries no `region`, because a line number there would be the invention above.
 *
 * Both are anchors and both say so. `sqlens-anchored` stays true either way — a migration is where
 * an object CAME FROM, never what the finding is about — and `sqlens-anchor-kind` says which of the
 * two a consumer is looking at.
 *
 * The anchor is honest only because the message says so. A catalog finding's SARIF text names its
 * object FIRST and states that the file is a stand-in, so nobody reads the alert as a finding about
 * `config/sqlens.php`. Without that sentence this class would be the second mistake wearing the
 * costume of the fix.
 */
final readonly class LocationResolver
{
    /** The file an alert about a live database is anchored to when a project configures none. */
    public const string DEFAULT_ANCHOR = 'config/sqlens.php';

    public function __construct(private string $anchorFile = self::DEFAULT_ANCHOR) {}

    /**
     * The `locations` array for one finding — never empty, whatever the finding is about.
     *
     * The guard rail this satisfies is a counting one: findings in must equal results out, and a
     * result SARIF rejected for want of a location is a finding that vanished between the run and
     * the report. Every branch below therefore returns something.
     *
     * @return non-empty-list<array<string, mixed>>
     */
    public function locations(Finding $finding): array
    {
        $location = $finding->location;

        if ($location->kind !== LocationKind::Catalog) {
            // A migration or callsite finding. The file is already repo-relative — `Location` does
            // that at construction — and the region is omitted rather than defaulted when the
            // finding has no line, because a file-level finding pinned to line 1 is the invention
            // this class exists to avoid.
            return [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => (string) $location->file],
                    ...($location->line === null ? [] : ['region' => ['startLine' => $location->line]]),
                ],
            ]];
        }

        // A catalog finding, and the branch is chosen on the KIND rather than on whether a file
        // happens to be set. That distinction is load-bearing since a catalog location can now
        // carry the migration that introduced its subject: branching on `file !== null` sent an
        // anchored finding down the migration path, which drops `logicalLocations` — so the alert
        // would lose the machine-readable identity of the object it is about, which is the half
        // this class exists to carry.
        $migration = $location->file;

        return [[
            'physicalLocation' => [
                'artifactLocation' => ['uri' => $migration ?? $this->anchorFile],
                ...($migration === null || $location->line === null ? [] : ['region' => ['startLine' => $location->line]]),
            ],
            'logicalLocations' => [$this->logical($location)],
            'properties' => [
                // The anchor, named as an anchor. A consumer reading the physical location alone
                // would otherwise have no way to know it is a stand-in rather than the subject.
                // TRUE in both cases: a migration is where the object CAME FROM, never what the
                // finding is about — the finding is about the object as the database holds it now.
                'sqlens-anchored' => true,
                // …and WHICH kind of anchor, because the two are worth different amounts to a
                // reader. `migration` is the file that introduced the subject, so the alert lands
                // on a line somebody is reading anyway; `configured` is a stand-in for an object
                // with no file at all. Additive, so a consumer that only knows the flag above is
                // unaffected.
                'sqlens-anchor-kind' => $migration === null ? 'configured' : 'migration',
            ],
        ]];
    }

    /**
     * The subject as SARIF's logical location.
     *
     * `fullyQualifiedName` deliberately omits the INSTANCE. It is a connection name — deployment
     * detail, different on a developer's machine and in CI — and a fully qualified name that moved
     * with the environment would give one object two identities, which is the opposite of what the
     * field is for. The instance travels in `properties` instead, where it describes the reading
     * rather than the object.
     *
     * @return array<string, mixed>
     */
    private function logical(Location $location): array
    {
        $name = (string) $location->objectName;
        $driver = $location->driver;

        return [
            'name' => $name,
            'fullyQualifiedName' => $driver === null ? $name : $driver.'.'.$name,
            // SARIF suggests values like `function` and `member` and does not restrict the field.
            // Ours are database object kinds, which is what a reader of this report needs — mapping
            // a table onto `type` because the spec lists it would be a translation nobody asked for
            // and nobody could invert.
            'kind' => $location->objectType instanceof SchemaObjectType ? $location->objectType->value : 'object',
            'properties' => [
                'driver' => $driver,
                'instance' => $location->instance,
            ],
        ];
    }

    /**
     * The finding's text, with the subject moved to the front when the alert is anchored.
     *
     * Only for the anchored case, and that asymmetry is deliberate. GitHub shows the anchor file in
     * the alert header, so the very first thing a reader sees is a file the finding is not about —
     * the message has to correct that before anything else. A migration finding needs no such
     * correction, and prefixing it would repeat what the header already says.
     */
    public function message(Finding $finding): string
    {
        $location = $finding->location;

        if ($location->kind !== LocationKind::Catalog) {
            return $finding->message;
        }

        // An anchored finding still needs the correction, and arguably needs it more: the header
        // now shows a real migration, so a reader has every reason to take the alert for a finding
        // about that file. It is not — the migration is where the object came from, and the finding
        // is about the object as the database holds it now. A `CREATE TABLE` that was correct on
        // the day it ran is the ordinary case.
        if ($location->file !== null) {
            return sprintf(
                '%s: %s (a live-database finding — this alert sits on the migration that introduced '
                .'%s, which is where it came from rather than what is being reported)',
                (string) $location->objectName,
                $finding->message,
                (string) $location->objectName,
            );
        }

        return sprintf(
            '%s: %s (a live-database finding — this alert is anchored to %s because the object it '
            .'reports has no file in the repository)',
            (string) $location->objectName,
            $finding->message,
            $this->anchorFile,
        );
    }
}
