<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Attribution;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * The published metadata a preflight or postdeploy check carries — the fifth finding family.
 *
 * ## Why these were invisible, and what it cost
 *
 * A deploy check builds its finding with `documentationUrl: RuleDocumentationUrl::for(self::ID)`, so
 * every one of them EMITS a stable address. None of them reached {@see RuleRegistryExport}, which is
 * what decides whether a page exists behind an address. Twelve ids therefore shipped a link to a
 * page nobody had written, and a baseline naming one of them was rejected as an unknown id — the
 * message meant for a typo.
 *
 * The export's own docblock had already recorded this exact shape once: *"The audit's own eighteen
 * were exactly that — written as literals, in no registry, each shipping a dead link."* This is the
 * same defect in a family that did not exist when that sentence was written.
 *
 * ## The values are MOVED, not chosen
 *
 * Each check already names its category, level and severity where it constructs the finding. This
 * record is where those values now live, and the check reads them from here — writing them a second
 * time would be the drift this package guards against everywhere else.
 *
 * ## A severity that is decided per finding is null, and SAYS so
 *
 * Three checks pick their severity from what they read: a replication slot is Low, Medium or High by
 * how far it has fallen behind; a server setting by which setting it is; a lock blocker by what the
 * blocking session is doing. A catalog naming ONE severity for those would be asserting something
 * the finding itself contradicts.
 *
 * So they carry `severity: null` together with {@see self::$severityDerived} — the same pair
 * `downtime_class` / `downtime_class_derived` already uses, and for the same reason: without the
 * second field, "has no severity" and "has three" are one value.
 *
 * ## The downtime class is declared here too, and the first version of this class got it wrong
 *
 * Seven of the twelve checks end their finding with `->withDowntimeClass(…)` — measured, and the
 * count is stated here only because the sentence below needs it. The five that do not are registered
 * WITH REASONS in `EveryDeployCheckIsInTheCatalogTest`, which is where the number actually lives: a
 * count in prose rots the first time somebody adds a check, and this one already had (it said
 * eight). The first version of
 * this record carried none at all, which the export writes as `downtime_class: null` with
 * `downtime_class_derived: false` — and that pair means "classifies no downtime whatsoever". So the
 * catalog said one thing while the finding beside it said `blocking`, and a page generated from the
 * catalog promised a reader something the report contradicts.
 *
 * Found by a verifier reading the emitted finding rather than the metadata. It is the same defect
 * this whole class exists to fix, one field over: a value that lives in two places and is stated in
 * only one of them.
 */
final readonly class DeployCheckMetadata
{
    /**
     * @param  list<Suite>  $suites
     * @param  non-empty-list<string>  $limitations  what this check deliberately does not answer
     */
    private function __construct(
        public string $id,
        public Category $category,
        public Level $level,
        public ?Severity $severity,
        public bool $severityDerived,
        public ?DowntimeClass $downtimeClass,
        public bool $downtimeClassDerived,
        public StabilityTier $stability,
        public string $messagePrefix,
        public array $suites,
        public array $limitations,
        /**
         * Whether this check names something the READER wrote, or something the run OBSERVED.
         *
         * This is the family the question was raised for, because it is the family that splits.
         * Twenty-two of these checks read the world — a lock another session holds, a replica
         * behind, an index whose build died, a privilege the role lacks — and for those an example
         * pair would be confident, concrete, and about something else. Two read a state a MIGRATION
         * left: a constraint added `NOT VALID` and never validated, and a MySQL check written
         * `NOT ENFORCED`. Those two have a clean pair and owe one.
         *
         * ⚠️ Required rather than defaulted, and the four name-based `LEGACY` checks are why. They
         * look authored — `orders_old`, `_t_gho`, an invalid index — and they are not: each says in
         * its own limitations that it cannot tell wreckage from a healthy in-flight state, so no
         * migration reliably causes them and none avoids them. A default would have classified all
         * six of that family the same way without anybody deciding, and a new check would inherit
         * whichever answer happened to be the default.
         *
         * {@see Attribution} carries the criterion and what each answer obliges.
         */
        public Attribution $attribution,
    ) {}

    /**
     * A check whose findings always carry the same severity.
     *
     * @param  list<Suite>  $suites
     * @param  non-empty-list<string>  $limitations
     */
    public static function fixed(
        string $id,
        Severity $severity,
        array $suites,
        array $limitations,
        Attribution $attribution,
        ?DowntimeClass $downtimeClass = null,
        bool $downtimeClassDerived = false,
        Category $category = Category::Safety,
        Level $level = Level::Capturable,
    ): self {
        return new self($id, $category, $level, $severity, false, $downtimeClass, $downtimeClassDerived, StabilityTier::Stable, DeployCheckCatalog::MESSAGE_PREFIX, $suites, $limitations, $attribution);
    }

    /**
     * A check that decides its severity from what it read.
     *
     * There is no `severity` argument, which is the point: the value is unconstructible here rather
     * than merely discouraged, so nobody can quietly pick one of the three and call it the answer.
     *
     * @param  list<Suite>  $suites
     * @param  non-empty-list<string>  $limitations
     */
    public static function derived(
        string $id,
        array $suites,
        array $limitations,
        Attribution $attribution,
        ?DowntimeClass $downtimeClass = null,
        bool $downtimeClassDerived = false,
        Category $category = Category::Safety,
        Level $level = Level::Capturable,
    ): self {
        return new self($id, $category, $level, null, true, $downtimeClass, $downtimeClassDerived, StabilityTier::Stable, DeployCheckCatalog::MESSAGE_PREFIX, $suites, $limitations, $attribution);
    }

    /**
     * The page this id resolves to, derived exactly like every other id's.
     *
     * Derived rather than stored, for the reason this whole class exists: an address written by hand
     * is one somebody can typo into a 404 that no test notices.
     */
    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->id);
    }
}
