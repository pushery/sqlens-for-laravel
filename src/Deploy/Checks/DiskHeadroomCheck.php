<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Catalog\Statistics\Estimate;
use Pushery\SQLens\Catalog\Statistics\StatisticsRequest;
use Pushery\SQLens\Catalog\Statistics\StatisticsSnapshot;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * How much space the pending migration will need, against what the instance can see.
 *
 * A table rewrite needs the table's size AGAIN while it runs — the old copy stays readable until the
 * new one is complete. An index build needs its own. If the instance fills up mid-rewrite the
 * database stops, which is the most expensive way a deploy can end.
 *
 * ## The honesty limit, stated first because it decides the shape
 *
 * Free filesystem space is usually NOT readable from inside the database. A managed instance does
 * not expose it at all, and no amount of privilege changes that — it is a fact about the host, and
 * this package will not shell out to a database server to learn it.
 *
 * So the check reports what it CAN establish: the estimated need. When headroom is unreadable it
 * ends `undetermined` with a named reason AND the number attached, because that number is the one
 * thing a human in a deploy window can hold against their own monitoring. An undetermined result
 * that also withheld the estimate would be correct and useless.
 *
 * ## Why it is a heuristic and says so
 *
 * The need is derived from current object sizes, and what a rewrite actually writes depends on fill
 * factor, TOAST, index rebuilds and the WAL the operation generates. A number that presented itself
 * as a measurement here would be worse than none: somebody would plan against it.
 */
final readonly class DiskHeadroomCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.DISK_HEADROOM';

    /**
     * @param  int|null  $declaredFreeBytes  what the OPERATOR says is free, from
     *                                       `deploy.predeploy.available_disk_bytes` — used only when
     *                                       the instance reports nothing, and never trusted silently
     */
    public function __construct(private ?int $declaredFreeBytes = null) {}

    /**
     * The statement kinds that need space AGAIN while they run.
     *
     * A rewrite keeps the old copy readable until the new one is complete, so the peak is roughly
     * double. `CreateIndex` needs the index rather than the table, which is smaller and still real.
     */
    private const array SPACE_HUNGRY_KINDS = [
        StatementKind::AlterTable,
        // `ADD COLUMN` is space-hungry whenever the server materializes the new value: a volatile
        // default rewrites the table on PostgreSQL, and MySQL rebuilds it under `ALGORITHM=COPY`.
        // It was missing here for the same reason it was missing from the schema-change rule —
        // MySQL already names the statement, so the check was already blind to it there.
        StatementKind::AddColumn,
        StatementKind::AlterColumn,
        StatementKind::AddPrimaryKey,
        StatementKind::CreateIndex,
    ];

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql' || $driver === 'mysql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        $targets = $this->spaceHungryTargets($context);

        if ($targets === []) {
            return CheckResult::pass(self::ID);
        }

        if (! $context->statistics instanceof StatisticsReader) {
            return CheckResult::undetermined(
                self::ID,
                'this run has no statistics reader, so how much space the pending rewrite needs '
                .'could not even be estimated. The operation still needs it.',
            );
        }

        try {
            $snapshot = $context->statistics->read(new StatisticsRequest($targets));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'the object sizes could not be read, so the space this migration needs is unknown: '
                .$failure->getMessage(),
            );
        }

        $needBytes = 0;
        $measured = 0;

        foreach ($targets as $target) {
            $bytes = $snapshot->forTable($target)?->totalBytes?->value;

            if ($bytes === null) {
                continue;
            }

            $needBytes += $bytes;
            $measured++;
        }

        if ($measured === 0) {
            return CheckResult::undetermined(
                self::ID,
                'none of the objects this migration rewrites reported a size, so the space it needs '
                .'could not be estimated. An unmeasured table is not a small one.',
            );
        }

        // The headroom half, and the one that usually cannot be answered. Reported as its own
        // undetermined WITH the estimate rather than swallowed: the number is what a human in a
        // deploy window holds against their own monitoring, and withholding it would make the
        // verdict correct and useless.
        $freeBytes = $this->freeBytes($snapshot);

        // The operator's own figure, and ONLY where the instance had nothing to say. A configured
        // number never overrides a measured one: a reading from the server is evidence, and a value
        // in a config file is a claim somebody typed once — quietly preferring the claim would be
        // the tool choosing the weaker source.
        $declared = $freeBytes === null && $this->declaredFreeBytes !== null && $this->declaredFreeBytes > 0;

        if ($declared) {
            $freeBytes = $this->declaredFreeBytes;
        }

        if ($freeBytes === null) {
            return CheckResult::undetermined(
                self::ID,
                sprintf(
                    'filesystem_headroom_unreadable: this instance does not report free space — on a '
                    .'managed database it never does, and no privilege changes that. What CAN be '
                    .'said: the pending rewrite touches %d object(s) totalling about %s, and a '
                    .'rewrite needs that much AGAIN while it runs because the old copy stays '
                    .'readable until the new one is complete. Hold that number against your own '
                    .'monitoring — or set `deploy.predeploy.available_disk_bytes` and this check '
                    .'will make the comparison for you. It is an ESTIMATE from current object '
                    .'sizes, not a measurement.',
                    $measured,
                    $this->humanBytes($needBytes),
                ),
            );
        }

        if ($freeBytes >= $needBytes) {
            return CheckResult::pass(self::ID);
        }

        return CheckResult::fail(self::ID, [$this->finding($context, $needBytes, $freeBytes, $measured, $declared)]);
    }

    /**
     * The instance's free space, when it reports any at all.
     *
     * Typed against the real snapshot rather than probed with `property_exists`: the first draft did
     * the latter, and a reflective read here would keep passing the day the field is renamed —
     * silently answering "no headroom reported" for an instance that reports it perfectly well.
     */
    private function freeBytes(StatisticsSnapshot $snapshot): ?int
    {
        foreach ($snapshot->headroom as $headroom) {
            $free = $headroom->freeBytes;

            if ($free instanceof Estimate) {
                return $free->value;
            }
        }

        return null;
    }

    /**
     * @param  bool  $declared  whether the free figure came from configuration rather than from the
     *                          instance — said out loud, because the two are not the same evidence
     */
    private function finding(PreflightContext $context, int $needBytes, int $freeBytes, int $objects, bool $declared): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The pending rewrite touches %d object(s) totalling about %s, and %s about %s free. '
                .'A rewrite needs the object\'s size AGAIN while it runs — '
                .'the old copy stays readable until the new one is complete — so this deploy is '
                .'estimated to need more space than there is. An instance that fills up mid-rewrite '
                .'stops, which is the most expensive way a deploy can end. This is an ESTIMATE from '
                .'current object sizes, not a measurement: what a rewrite actually writes depends on '
                .'fill factor, TOAST, index rebuilds and the WAL it generates.',
                $objects,
                $this->humanBytes($needBytes),
                // WHOSE number this is, in the sentence itself. A configured figure is a claim
                // nothing here can verify, and one set once when the volume was new tells this gate
                // that a full disk is empty — a reader has to know which of the two they are acting
                // on before they act on it.
                $declared
                    ? 'your configured `deploy.predeploy.available_disk_bytes` claims'
                    : 'the instance reports',
                $this->humanBytes($freeBytes),
            ),
            location: Location::inCatalog($context->driver, $context->connection, 'storage', SchemaObjectType::Database),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::High,
        )->withDowntimeClass(DowntimeClass::Rewrite)
            // Heuristic, and it says so on the finding as well as in the text. A reader filtering on
            // confidence must be able to tell this from a fact the catalog stated.
            ->withConfidence(Confidence::Heuristic);
    }

    /**
     * The objects this migration will need space for.
     *
     * @return list<string>
     */
    private function spaceHungryTargets(PreflightContext $context): array
    {
        $targets = [];

        foreach ($context->pending->statements as $statement) {
            if (! in_array($statement->statementKind, self::SPACE_HUNGRY_KINDS, true)) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                $targets[] = $target->qualifiedName();
            }
        }

        return array_values(array_unique($targets));
    }

    /** A size a human reads, rounded rather than precise — precision here would imply measurement. */
    private function humanBytes(int $bytes): string
    {
        return match (true) {
            $bytes >= 1024 ** 3 => number_format($bytes / 1024 ** 3, 1).' GiB',
            $bytes >= 1024 ** 2 => number_format($bytes / 1024 ** 2, 1).' MiB',
            default => number_format($bytes / 1024, 1).' KiB',
        };
    }
}
