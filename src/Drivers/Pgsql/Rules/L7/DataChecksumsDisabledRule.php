<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL cluster initialized without data checksums.
 *
 * ## What actually goes wrong
 *
 * Without checksums, a page corrupted by failing hardware — a bad disk, bad memory, a firmware bug —
 * is read back and served as data. Nothing raises, nothing logs; the row is simply wrong from then
 * on, and it propagates into backups, into replicas, and into every report built on it. With
 * checksums the read fails loudly instead, which is the entire point: the corruption still happened,
 * but it is now an incident rather than a silent fact about the database.
 *
 * PostgreSQL 18's `initdb` turns them on by default, so a cluster without them on 18 is almost
 * always an older one carried forward through `pg_upgrade`, where the original decision was made
 * years ago by someone who is probably not around to be asked.
 *
 * ## Why the remediation is worded the way it is
 *
 * This cannot be fixed in place while running. `pg_checksums` requires the cluster to be shut down
 * cleanly, and the alternative is a new cluster and a dump/restore. A rule proposing an online
 * change here would be proposing something impossible, and a tool that suggests impossible fixes
 * gets dismissed — along with its correct findings.
 *
 * ⚠️ **But it is not UNFIXABLE, and the sentence a reader actually saw said it was.** This paragraph
 * has been right since it was written; `changeable` was `initdb`, and that enum case renders *moving
 * it means a new cluster and a dump/restore*. So the docblock described `pg_checksums` while the
 * finding recommended a migration. It is `SettingChangeCost::Offline` now — changeable in place, with
 * the server stopped — which is the distinction between a maintenance window and a data migration,
 * and those differ by orders of magnitude.
 *
 * That is also why this rule carries NO `downtime_class`. The field describes what an OPERATION
 * costs, and the operation here is not a migration step at all — it is a stopped server and a pass
 * over the data directory. Stamping it `online` because the finding is harmless to produce would be
 * read literally by a deploy script or an agent payload as "this correction is free", which is the
 * opposite of true. The load-bearing fact is `changeable: offline`, which the matrix carries and
 * {@see AbstractServerSettingRule::remediation()} turns into the honest sentence.
 */
final class DataChecksumsDisabledRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L7.DATA_CHECKSUMS_DISABLED';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'data_checksums';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp($serverValue, $expectation->expectation ?? 'on') === 0) {
            return null;
        }

        return sprintf(
            'this cluster was initialized without data checksums, so a page corrupted by failing '.
            'hardware is read back and served as data — nothing raises, nothing logs, and the wrong '.
            'row propagates into backups and replicas. With checksums the read fails loudly instead: '.
            'the corruption still happened, but it becomes an incident rather than a silent fact. '.
            'PostgreSQL 18 initializes clusters with checksums on, so this is almost always an older '.
            'cluster carried forward through pg_upgrade. %s',
            $this->remediation($expectation),
        );
    }
}
