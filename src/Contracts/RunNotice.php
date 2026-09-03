<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * Something a RUN reports about itself, as opposed to something a rule reports about a statement.
 *
 * "The lint run found no active rules" and "the audit could not read table statistics" are the same
 * kind of thing: a fact about what the run was able to do, carrying an id, a documentation page and
 * the axes a report shows. They differ only in which suite produced them.
 *
 * The contract exists because the registry export — the artifact that answers "does every finding
 * this package can emit have a page" — has to see ALL of them. A second notice family that the
 * export did not know about would be a family of ids with no page and nothing to notice the gap,
 * which is precisely the drift the export was built to make impossible.
 */
interface RunNotice
{
    /** The id a report shows, and the key the documentation page is derived from. */
    public function id(): string;

    /** The message prefix this notice reports under — the runner, never a rule. */
    public function messagePrefix(): string;

    /**
     * Whether the id names a FAMILY of concrete ids rather than one exact id.
     *
     * A family shares one page: what a reader needs to know is the same across its members, and a
     * page per member would be the same sentence written many times and maintained none.
     */
    public function coversFamily(): bool;

    public function category(): Category;

    public function level(): Level;

    public function stability(): StabilityTier;

    /** The documentation page for this notice, derived like every other id's. */
    public function documentationUrl(): string;

    /**
     * The severity this notice's finding carries, or null when it carries none.
     *
     * ⚠️ NULLABLE BECAUSE ALMOST NONE OF THEM HAVE ONE, AND ONE OF THEM DOES. The registry export
     * used to stamp `severity: null` on every runner notice under a comment saying they are "never
     * severity-gated" — and `DEBT.UNRECORDED` had carried `Severity::Info` all along. The published
     * artifact therefore told a consumer that a rule has no severity while the shipped finding had
     * one, and the severity there is not decoration: `DebtThresholds::escalate()` ages a debt from
     * `info` through `low` to `high`, so a consumer reading the artifact sorted away a rule that
     * escalates.
     *
     * The alternative was to drop the severity from the finding, which would have made the finding
     * wrong to keep an artifact quiet. `CarriesNoSeverity` gives the families that genuinely have
     * none their answer in one place, so the slot costs them nothing.
     */
    public function severity(): ?Severity;

    /**
     * The suites this notice can appear in.
     *
     * Stated rather than left implicit: the export lists notices next to rules, and an empty list
     * there would read as "belongs nowhere" instead of "belongs to the run".
     *
     * @return list<Suite>
     */
    public function suites(): array;
}
