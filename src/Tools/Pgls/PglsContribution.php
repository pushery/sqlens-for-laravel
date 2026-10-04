<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Illuminate\Contracts\Config\Repository as Config;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\ToolContribution;
use Pushery\SQLens\Tools\ToolDiagnostic;
use Pushery\SQLens\Tools\ToolFindingGate;

/**
 * Folds the Postgres Language Server's schema findings into an audit run.
 *
 * ## The merge is one-directional
 *
 * The run's own findings are what they were with the tool and without it. This adds; it never
 * removes, re-ranks or re-decides one of them. A machine with the binary installed must not gate
 * differently from one without it — beyond having MORE checks, which is the entire point of an
 * amplifier.
 *
 * ## Why a performance rule is skipped and an unknown security rule is not
 *
 * `dblint` runs performance rules alongside the security ones. Those are out of this adapter's
 * scope: it has no summary for them, no help link, no severity translation, and reporting them
 * would put findings into a SECURITY suite that were never security findings.
 *
 * A rule inside the security namespace that this build's catalog does not describe is a different
 * thing entirely — that is a NEWER binary, and it is reported as an `undetermined` rather than
 * dropped. Dropping it would hide that the tool now checks something this package has not looked
 * at, which is the same silence the whole design refuses.
 *
 * Nothing here throws. Every way this can fail ends as a named finding.
 */
final readonly class PglsContribution implements ToolContribution
{
    public function toolName(): string
    {
        return new PglsTool()->name();
    }

    public function __construct(
        private PglsRunner $runner,
        private PglsFindingMapper $mapper,
        private PglsRuleMap $map,
        private Config $config,
        /**
         * Where the configured session bounds come from, so the tool's sessions run under the ones
         * the catalog reader's do. Null leaves the invocation on the shipped defaults.
         */
        private ?ReaderConnectionFactory $readers = null,
    ) {}

    /**
     * @param  list<Finding>  $own  the findings the run's own rules produced
     * @return list<Finding>
     */
    public function contribute(array $own, ToolDiagnostic $diagnostic, string $connectionName, SubjectContext $context, ?string $pinnedHost = null, ToolFindingGate $gate = new ToolFindingGate(new LevelGate(Level::Pedantic), new CategoryFilter([]))): array
    {
        // An unavailable tool is already reported by the run's missing-tool notice, which says what
        // it would have added and why it did not run. A second sentence here would be the same
        // absence counted twice.
        if (! $diagnostic->isAvailable() || $diagnostic->path === null) {
            return $own;
        }

        // The server the audit read: the connection as the catalog reader resolves it, with the host
        // the run pinned. Read raw, a `url` connection named no host at all, and one that kept
        // Laravel's defaults beside its `url` sent the tool to 127.0.0.1.
        $connection = PglsConnection::fromConfig(EffectiveConnectionConfig::forReading(
            $this->config->get('database.connections.'.$connectionName),
            $pinnedHost,
        ));

        if (! $connection instanceof PglsConnection) {
            return [...$own, $this->mapper->unavailable(
                PglsFailureReason::ConnectionIncomplete,
                sprintf('the connection "%s" does not name a host, database and username together', $connectionName),
                $connectionName,
                $context,
            )];
        }

        $result = $this->runner->run($diagnostic->path, new PglsInvocation($connection, $this->timeout(), $connectionName, $this->readers?->budget()));

        if (! $result->produced()) {
            return [...$own, $this->mapper->unavailable(
                $result->failure ?? PglsFailureReason::RunFailed,
                $result->detail,
                $connectionName,
                $context,
            )];
        }

        $version = $diagnostic->version ?? 'an unnamed build';
        $mapped = [];

        foreach ($result->findings as $raw) {
            if (! str_starts_with($raw->category, $this->map->categoryPrefix)) {
                continue;
            }

            $mapped[] = $this->mapper->map($raw, $version, $connectionName, $context);
        }

        // Merged rather than appended. Where the tool agrees with a finding this run already made,
        // the agreement becomes a CONFIRMATION on ours and the duplicate goes — a reader handed the
        // same advice twice starts skimming, and the next thing they skim is the finding they had
        // not seen. Our own findings are never dropped or changed by anything the tool said.
        return new PglsDeduplicator($version)->merge($own, $gate->apply($mapped))->all();
    }

    /**
     * Every id the catalog maps when the gate leaves security out, and none otherwise: each verdict
     * of this adapter has the same category and level.
     *
     * @return list<string>
     */
    public function unaskedIds(ToolFindingGate $gate): array
    {
        if ($gate->asks(PglsFindingMapper::LEVEL, PglsFindingMapper::CATEGORY)) {
            return [];
        }

        return array_map(static fn (string $rule): string => PglsFindingMapper::ID_PREFIX.$rule, $this->map->ruleNames());
    }

    /**
     * Seconds, from the project's own configuration.
     *
     * Read here rather than defaulted in the invocation, so a project that raised it for a large
     * schema raises it for real. A non-integer or non-positive value falls back to the invocation's
     * own default rather than failing the run: the config schema already rejects both, so reaching
     * this branch means the schema was bypassed, and an amplifier is not where that gets reported.
     */
    private function timeout(): float
    {
        $configured = $this->config->get('sqlens.tools.pgls.timeout');

        return is_int($configured) && $configured > 0 ? (float) $configured : new PglsInvocation(
            new PglsConnection('', 0, '', ''),
        )->timeoutSeconds;
    }
}
