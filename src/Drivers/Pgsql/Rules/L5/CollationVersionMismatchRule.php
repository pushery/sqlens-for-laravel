<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A collation whose recorded version no longer matches the one installed.
 *
 * ## What actually goes wrong
 *
 * A B-tree index on a text column stores its entries in the collation's sort order. Change the
 * collation — a glibc upgrade, a new ICU, an OS image bump — and that order changes underneath the
 * index. The index is now sorted by rules the server no longer uses, so an equality lookup can miss
 * a row that is present and a unique constraint can stop rejecting a duplicate.
 *
 * Nothing raises. The database is not corrupt in any way a checksum would notice; it is merely
 * answering questions with an index built to a different set of rules.
 *
 * PostgreSQL records the collation version at creation precisely so this is DETECTABLE, and it warns
 * once at startup. A warning in a log nobody reads is what this rule turns into a finding.
 *
 * ## The three-valued ladder, and why every rung is separate
 *
 * A version comparison has three genuinely different "cannot answer" cases, and collapsing any of
 * them into a pass is a silent green:
 *
 * 1. NEITHER side reports a version. This provider does not report one on this platform — measured
 *    on PostgreSQL 18 on macOS, the `libc` provider reports none at all. Drift is undetectable here
 *    in principle, which is not the same as absent.
 * 2. ONE side reports and the other does not. A recorded version with no current one means the
 *    provider stopped reporting — an OS change already happened and the evidence is gone. The
 *    reverse means the object predates version tracking.
 * 3. Both present and different — the finding.
 *
 * ## Why the comparison is a plain string equality
 *
 * PostgreSQL's own drift check is string equality, and the three providers report incomparable
 * formats: ICU says `153.128.47`, the builtin provider says `1`, glibc says `2.36`. Parsing those
 * into an ordering would invent one across three incompatible schemes and would make `2.9` newer
 * than `2.36`.
 *
 * ## The remediation order is load-bearing
 *
 * `REINDEX` first, `REFRESH VERSION` second. Refreshing first tells the server the recorded version
 * is current while the indexes are still sorted the old way — it silences the warning and leaves the
 * corruption, which is worse than doing nothing. The message states them in that order and a test
 * pins the ORDER rather than the presence of both words.
 */
final class CollationVersionMismatchRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Collations only. The reading is its own catalog surface, so an audit that could not read it
     * leaves this rule without a subject rather than with nothing to report.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Collation];
    }

    public function id(): string
    {
        return 'PG.L5.COLLATION_VERSION_MISMATCH';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    /**
     * `blocking`, and this rule is the one place that value is right for an audit finding.
     *
     * The field prices an OPERATION. A server-baseline rule describes a configuration and prices
     * nothing, which is why those carry none — see the argument on the settings family. Here there
     * genuinely is one: the correction is `REINDEX`, which takes a lock and rebuilds the index, and
     * a deploy pipeline reading this field needs to know that before it schedules the work.
     *
     * Stated on the recommended CORRECTION rather than on the finding: producing the finding costs
     * nothing at all. That reading is the one the field has to carry consistently, and it is what
     * makes `blocking` here and `null` on a settings rule the same rule rather than two.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Collation) {
            return [];
        }

        $recorded = (string) $object->getString('recorded_version');
        $actual = (string) $object->getString('actual_version');
        $provider = (string) $object->getString('provider');
        $locale = (string) $object->getString('locale');

        if ($recorded === '' && $actual === '') {
            return [RuleVerdict::undetermined(
                sprintf(
                    'the %s provider reports no collation version for %s on this platform, so whether '.
                    'its sort order has changed since the indexes were built cannot be determined '.
                    'here at all. This is a limit of the provider, not a privilege or a reading '.
                    'failure — and it is why a database on a versionless provider gets no warning '.
                    'from PostgreSQL either.',
                    $provider,
                    $locale === '' ? $object->qualifiedName : $locale,
                ),
                UndeterminedReason::StructurallyNotApplicable,
            )];
        }

        if ($recorded === '' || $actual === '') {
            return [RuleVerdict::undetermined(
                sprintf(
                    '%s reports %s. A recorded version with no current one means the provider stopped '.
                    'reporting — an operating-system change has already happened and the evidence of '.
                    'what it was is gone; a current version with nothing recorded means the object '.
                    'predates version tracking. Neither is a pass, and neither is a failure.',
                    $object->qualifiedName,
                    $recorded === ''
                        ? sprintf('a current version (%s) but nothing recorded', $actual)
                        : sprintf('a recorded version (%s) but no current one', $recorded),
                ),
                UndeterminedReason::StructurallyNotApplicable,
            )];
        }

        if ($recorded === $actual) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s was created against %s version %s and the installed one is now %s. Every B-tree index '.
            'on a text column using it is sorted by rules the server no longer applies, so an '.
            'equality lookup can miss a row that is present and a unique constraint can stop '.
            'rejecting a duplicate — with nothing raising, because the data is not corrupt, it is '.
            'merely indexed to a different order. REINDEX the affected indexes FIRST, then run '.
            'REFRESH VERSION: refreshing first records the new version while the indexes are still '.
            'sorted the old way, which silences the warning and leaves the problem.',
            $object->qualifiedName,
            $provider,
            $recorded,
            $actual,
        ))];
    }
}
