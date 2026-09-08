<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Categories\CategorySelection;
use Pushery\SQLens\Config\ConfigIgnoreReferences;
use Pushery\SQLens\Config\ConfigViolation;
use Pushery\SQLens\Config\RuleIdValidator;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;
use Pushery\SQLens\Reporting\Baseline\EmittableIds;
use Pushery\SQLens\Rules\RuleRegistry;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\VersionRuleGate;
use Pushery\SQLens\Severity\Severity;

/**
 * Which rules apply to THIS project, right now — the one place that answers it.
 *
 * ## Why this exists beside the rule registry
 *
 * The registry knows every rule this package ships. That is a different question from the one an
 * agent needs answered, which is: given this project's level, categories, driver, stability
 * opt-in, ignore list and server version, which checks will a run actually apply? Preventive
 * guidance built from the first question tells somebody about rules their pipeline never runs —
 * and, worse, stays silent about the difference. Guidance and enforcement then drift with nothing
 * to notice, which is the failure this whole export chain is arranged to make impossible.
 *
 * ## It selects; it never decides
 *
 * Each axis has an owner, and this resolver calls it rather than reproducing it: the level gate,
 * the category filter, the stability gate, the version gate, the rule-id validator. A second
 * implementation of any of them would agree for a long time and then disagree once, quietly, in
 * exactly the direction nobody checks. The order is the runner's order, for the same reason.
 *
 * ## No database, by construction
 *
 * `sqlens:agent-rules` runs where there is no server to ask — a fresh checkout, a CI image, an
 * agent working offline. So this reads rule METADATA and configuration only. Nothing here opens a
 * connection, and the version comes from the `assume_server_version` pin or from nowhere.
 *
 * ## What "from nowhere" means, precisely
 *
 * Without a pin there is no server version, and a version-gated rule cannot be placed. It is
 * INCLUDED and marked version-dependent, never dropped and never judged against a default:
 * dropping it silently would leave a hole in the preventive knowledge exactly where the risky
 * rules live, and assuming a version would reproduce the environment skew the pin exists to
 * remove. The mark is what lets a renderer say "this one depends on your server version" instead
 * of implying it always applies.
 */
final readonly class ActiveRuleResolver
{
    /**
     * @param  string|null  $metadataPath  the shipped rule metadata to join against; null takes the
     *                                     artifact that ships with this package. A parameter only
     *                                     so the join's own refusals are reachable — a refusal
     *                                     nothing can exercise is one nobody has checked.
     */
    public function __construct(
        private Repository $config,
        private DriverRegistry $drivers,
        private ?string $metadataPath = null,
    ) {}

    /**
     * The active rule set as a snapshot, or a named refusal.
     *
     * @param  string|null  $driverKey  the engine to describe; null takes the configured connection's
     * @param  int|null  $level  overrides `sqlens.level`, as the commands' `--level` does
     * @param  list<string>|null  $categories  overrides `sqlens.categories`, as `--category` does
     * @param  string|null  $connection  the connection whose driver to describe, as `--connection` does
     *
     * @throws UnresolvableRuleCatalog
     */
    public function resolve(?string $driverKey = null, ?int $level = null, ?array $categories = null, ?string $connection = null): RuleCatalogSnapshot
    {
        $driver = $this->driver($driverKey, $connection);
        $active = Level::tryFrom($level ?? $this->configuredLevel());

        if (! $active instanceof Level) {
            throw UnresolvableRuleCatalog::unknownLevel($level ?? $this->configuredLevel());
        }

        $selection = CategorySelection::forRun($categories, $this->config->get('sqlens.categories'));
        $stability = StabilityGate::fromConfig($this->config->get('sqlens.stability'));
        $version = $this->pinnedVersion($driver);

        // Every rule the driver ships, every suite. The lint runner narrows to its own suite
        // because it is about to EVALUATE them; this is preventive knowledge, and a project is no
        // less bound by an audit rule than by a lint one. Each entry carries its suites, so a
        // renderer that wants one can filter — from data, rather than from a decision taken here
        // that no reader could see.
        $registry = RuleRegistry::fromRules([...$driver->rules()]);

        // The runner's order, deliberately: level, then category over what level admitted, then
        // stability over what category kept, then version last. The axes are not commutative —
        // the counts each one reports are about the set it was handed — so a second order here
        // would produce a catalog that disagrees with the run it claims to describe.
        $gated = $stability->apply(new CategoryFilter($selection->categories)->apply(new LevelGate($active)->active($registry)));

        $ignored = $this->projectWideIgnores();
        $gated = array_values(array_filter($gated, static fn (Rule $rule): bool => ! in_array($rule->id(), $ignored, true)));

        $versionGate = new VersionRuleGate($version);

        return RuleCatalogSnapshot::of(
            applies: $versionGate->active($gated),
            versionDependent: $versionGate->undetermined($gated),
            context: new RuleCatalogContext(
                driver: $driver->key(),
                profile: $this->stringConfig('sqlens.profile') ?? 'local',
                level: $active->value,
                categories: array_map(static fn (Category $category): string => $category->value, $selection->categories),
                stability: $this->admittedTiers($stability),
                serverVersion: $version?->toString(),
                minSeverity: $this->configuredMinSeverity(),
                ignoredRuleIds: $ignored,
            ),
            metadata: $this->metadataPath === null
                ? ShippedRuleMetadata::shipped()
                : ShippedRuleMetadata::keyed($this->metadataPath),
        );
    }

    /**
     * The driver whose rule set this describes.
     *
     * Resolved from configuration rather than from a live connection: the point of this layer is
     * to work where no server is reachable. `database.connections.<name>.driver` is a static
     * declaration, so reading it costs nothing and asks nobody.
     */
    private function driver(?string $driverKey, ?string $connection = null): Driver
    {
        if ($driverKey === null) {
            // The named connection first, then the configured one, then the framework default. A
            // project whose dev default is an engine this package has no rules for still has a
            // production connection worth describing, and refusing to describe it because of what
            // `database.default` happens to say would make the command unusable in exactly the
            // projects most likely to want it.
            $connection ??= $this->stringConfig('sqlens.connection')
                ?? $this->stringConfig('database.default')
                ?? 'default';

            $driverKey = $this->stringConfig('database.connections.'.$connection.'.driver');

            if ($driverKey === null) {
                throw UnresolvableRuleCatalog::noDriverConfigured($connection);
            }
        }

        $driver = $this->drivers->resolve($driverKey);

        if (! $driver instanceof Driver) {
            throw UnresolvableRuleCatalog::unknownDriver($driverKey, $this->drivers->keys());
        }

        return $driver;
    }

    /**
     * The pinned server version, or null when nothing is pinned.
     *
     * An UNREADABLE pin is a refusal rather than a fall back to null. The two look alike from
     * here and are opposites to the person who wrote it: one is "I did not say", the other is "I
     * said, and you misread me" — and answering the second with the unpinned catalog hands them a
     * different world under the name they chose.
     */
    private function pinnedVersion(Driver $driver): ?ServerVersion
    {
        $pin = $this->stringConfig('sqlens.assume_server_version');

        if ($pin === null) {
            return null;
        }

        $parsed = ServerVersion::parsePin($pin, $driver->key());

        if ($parsed instanceof UndeterminedReason) {
            throw UnresolvableRuleCatalog::unreadablePin($pin, $driver->key());
        }

        return $parsed;
    }

    /**
     * The rule ids this project has switched off everywhere.
     *
     * Only the UNSCOPED entries. An ignore limited to `paths` or `suites` still leaves the rule in
     * force elsewhere, so removing it from the catalog would understate what a run checks — and
     * the direction of that error matters: a rule an agent was not told about is a finding it did
     * not prevent. An entry with neither scope genuinely is not in force, and listing it would
     * be advice about a check that will never run.
     *
     * A typo is a refusal, not a skip. That is the same reading the config validator gives the
     * same list, and it is the expensive case: an ignore that silently matches nothing leaves the
     * rule firing while somebody believes it is off.
     *
     * @return list<string>
     */
    private function projectWideIgnores(): array
    {
        $configured = $this->config->get('sqlens.ignore');

        if (! is_array($configured)) {
            return [];
        }

        // The references come from the shared reader, so the lint run and this one cannot end up
        // with different opinions about the same file.
        $references = ConfigIgnoreReferences::of($configured);
        $ignored = [];

        foreach (array_values($configured) as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            if (! is_string($entry['rule'] ?? null)) {
                continue;
            }

            if (($entry['paths'] ?? []) === [] && ($entry['suites'] ?? []) === []) {
                $ignored[] = $entry['rule'];
            }
        }

        $violations = new RuleIdValidator(
            RuleRegistry::fromRules($this->everyRule()),
            EmittableIds::shipped()->all(),
            // The tools' namespaces, derived. A catalog built for an agent must not refuse a
            // configuration a lint run accepts — two commands reading one file and disagreeing
            // about it is the drift this whole seam exists to prevent.
            $this->drivers->everyToolPrefix(),
        )->unknown($references);

        if ($violations !== []) {
            throw UnresolvableRuleCatalog::unknownRuleIds(
                array_map(static fn (ConfigViolation $violation): string => $violation->message(), $violations),
            );
        }

        sort($ignored, SORT_STRING);

        return array_values(array_unique($ignored));
    }

    /**
     * Every rule of every driver — the population an ignore id is checked against.
     *
     * Wider than the driver being described on purpose. A project that runs PostgreSQL in
     * production and MySQL in one service legitimately writes both engines' ids into one ignore
     * list, and refusing the other engine's id would turn a correct configuration into an error
     * that depends on which catalog somebody happened to ask for.
     *
     * Keyed by id, because a driver-neutral rule is registered by EVERY driver and the registry
     * refuses a duplicate id outright — correctly, since ids are public API and "last wins" would
     * make which rule answers depend on registration order. Here the duplicate is expected rather
     * than suspicious: it is one rule reachable through two doors, and the ignore list only needs
     * to know the id exists. This is the same first-wins reading the rule-registry export gives
     * the same collision.
     *
     * @return list<Rule>
     */
    private function everyRule(): array
    {
        $rules = [];

        foreach ($this->drivers->all() as $driver) {
            foreach ($driver->rules() as $rule) {
                $rules[$rule->id()] ??= $rule;
            }
        }

        return array_values($rules);
    }

    /**
     * The stability tiers this configuration admits, as names.
     *
     * Asked of the gate rather than read off the config value, so the answer includes the tier
     * that is on by default and never contradicts what `apply()` just did.
     *
     * @return list<string>
     */
    private function admittedTiers(StabilityGate $gate): array
    {
        $admitted = array_filter(StabilityTier::cases(), $gate->admits(...));

        return array_values(array_map(static fn (StabilityTier $tier): string => $tier->value, $admitted));
    }

    /** The configured level, defaulting to the shipped 0 when the key is absent or malformed. */
    private function configuredLevel(): int
    {
        $level = $this->config->get('sqlens.level');

        return is_int($level) ? $level : 0;
    }

    /**
     * The configured security floor, or null when the axis is genuinely off.
     *
     * A value that cannot be read is a refusal, not a null — the same answer the unreadable pin
     * gets, for the same reason and with more at stake. Falling back to "no floor" is the LOOSE
     * direction: with the severity axis off, every security rule is advisory, so a typo would
     * quietly turn a catalog that says "these block your deploy" into one that says "these are
     * worth reading". The config validator refuses the value before a run starts, which makes this
     * unreachable on a validated configuration — a defense being unreachable in practice is what a
     * defense looks like when everything else works.
     */
    private function configuredMinSeverity(): ?string
    {
        $configured = $this->stringConfig('sqlens.security.min_severity');

        if ($configured === null) {
            return null;
        }

        $severity = Severity::tryFrom($configured);

        if (! $severity instanceof Severity) {
            throw UnresolvableRuleCatalog::unreadableSeverityFloor($configured);
        }

        return $severity->value;
    }

    /** A configuration value that is a non-empty string, or null — the shape every read here wants. */
    private function stringConfig(string $key): ?string
    {
        $value = $this->config->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
