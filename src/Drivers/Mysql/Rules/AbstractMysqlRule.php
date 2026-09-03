<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules;

use Override;
use Pushery\SQLens\Rules\AbstractSafetyRule;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * The base of the MySQL safety-rule family.
 *
 * Everything a rule needs — identity derivation, the canonical-only judge()/verdict()
 * seam, the finding's shape, the metadata defaults (including the version window that
 * carries `minVersion`/`maxVersion`) — lives on the driver-neutral {@see AbstractSafetyRule}
 * in Core, because none of it is MySQL-specific: the very same base carries the PostgreSQL
 * family and the driver-neutral lifecycle rules. This class adds nothing but a name, so the
 * MySQL rules read as a family and a future MySQL-only convention has one obvious home. The
 * inherited `DOCUMENTATION_BASE` constant and `slug()` helper stay reachable as
 * `AbstractMysqlRule::…`, so the MySQL completeness test needs no change.
 *
 * The one thing it does add is the VERSION FLOOR, and it belongs to the family rather than to each
 * rule. Every rule here was written against MySQL 8.4 — the online-DDL matrix it reads is keyed per
 * version window, the behaviors it reports were measured on 8.4, and the driver refuses to run
 * against anything older. A rule that left its window unbounded would be claiming to hold on
 * versions nobody checked it against, which is the cargo-cult the version axis exists to prevent.
 * Declared once, so no rule can forget it and none can quietly disagree.
 */
abstract class AbstractMysqlRule extends AbstractSafetyRule
{
    /** The engine floor this family was written against, and the floor the driver enforces. */
    public const string MINIMUM_SERVER_VERSION = '8.4';

    #[Override]
    public function versionWindow(): VersionWindow
    {
        return VersionWindow::from(ServerVersion::of(8, 4, 0, 'mysql'));
    }
}
