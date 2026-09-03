<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Sarif;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
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
 * - `physicalLocation` carries an ANCHOR: one configurable repository file, `config/sqlens.php` by
 *   default, chosen because it is the file a reader would edit in response. It has no `region`, and
 *   the omission is the point — a line number here would be the invention above.
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
        $file = $finding->location->file;

        if ($file !== null) {
            // A migration or callsite finding. The file is already repo-relative — `Location` does
            // that at construction — and the region is omitted rather than defaulted when the
            // finding has no line, because a file-level finding pinned to line 1 is the invention
            // this class exists to avoid.
            return [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => $file],
                    ...($finding->location->line === null ? [] : ['region' => ['startLine' => $finding->location->line]]),
                ],
            ]];
        }

        return [[
            'physicalLocation' => ['artifactLocation' => ['uri' => $this->anchorFile]],
            'logicalLocations' => [$this->logical($finding->location)],
            'properties' => [
                // The anchor, named as an anchor. A consumer reading the physical location alone
                // would otherwise have no way to know it is a stand-in rather than the subject.
                'sqlens-anchored' => true,
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
        if ($finding->location->file !== null) {
            return $finding->message;
        }

        return sprintf(
            '%s: %s (a live-database finding — this alert is anchored to %s because the object it '
            .'reports has no file in the repository)',
            (string) $finding->location->objectName,
            $finding->message,
            $this->anchorFile,
        );
    }
}
