<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What a settings read produced — the settings, and whether the reading itself got that far.
 *
 * A bare map cannot say the difference between "the server has nothing to report" and "the read
 * never happened", and both come out as zero entries. That ambiguity is not theoretical: it made a
 * wrong diagnosis look plausible for half an hour during development, when a test's role did not
 * exist and the reader answered with the same empty result an unreachable server gives. A rule
 * consuming that map can tell them apart no better than a person can.
 *
 * So the reading carries its own outcome. A rule that finds no entry for its name still reports
 * "could not check" — that part was always right — but a run can now say WHY the whole set is
 * missing instead of implying the server simply had nothing.
 */
final readonly class SettingsReading
{
    /**
     * @param  array<string, Setting>  $settings
     */
    private function __construct(
        public array $settings,
        /** Why the read did not happen, or null when it did. */
        public ?UndeterminedReason $failure = null,
        /**
         * Whether the reading role may see every setting, or null when the engine cannot say.
         *
         * The answer to "why is this name missing?" — and the reason it belongs on the READING
         * rather than being inferred per lookup. A restricted role loses whole rows silently
         * (measured: 374 of 397 on PostgreSQL 18, no null, no error), so a consumer that found no
         * entry could otherwise not tell "this server does not have that setting" from "you were
         * not allowed to see it". Those send a reader to entirely different places.
         */
        public ?bool $sawEverything = null,
        /**
         * Whether the values carry where they came from, or the reading had to do without.
         *
         * Not cosmetic. "Set in a config file" and "still the compiled-in default" call for
         * different actions, so a rule that reasons about PROVENANCE must be able to tell that the
         * reading simply could not supply it — otherwise a missing source reads as "nobody
         * configured this", which is a claim about the server rather than about the reading.
         */
        public bool $carriesSources = true,
        /**
         * What the server or the driver actually said when the reading failed.
         *
         * A reason names the CLASS of failure; this names the instance of it. The difference is not
         * decoration: during development a reading failed with `role does not exist` and, with only
         * the class visible, it looked exactly like a role that was allowed to see nothing. Half an
         * hour went into a bug that was not there.
         *
         * Never shown to a user as-is — a driver message can carry a host and a database name — but
         * available to whoever is diagnosing, which is the difference between a dead end and a
         * question with an answer.
         */
        public ?string $failureDetail = null,
    ) {}

    /** @param  array<string, Setting>  $settings */
    public static function of(array $settings, ?bool $sawEverything = null, bool $carriesSources = true): self
    {
        return new self($settings, null, $sawEverything, $carriesSources);
    }

    /**
     * The read never happened, for a named reason.
     *
     * Distinct from `of([])`, which is a successful read of a server that reported nothing — a
     * state no real server produces, and therefore one that should look different in a report from
     * the failure that produces it constantly.
     */
    public static function failed(UndeterminedReason $reason, ?string $detail = null): self
    {
        return new self([], $reason, null, true, $detail);
    }

    public function succeeded(): bool
    {
        return ! $this->failure instanceof UndeterminedReason;
    }

    /**
     * Why a name might be absent from this reading — or null when it would not be.
     *
     * Deliberately never "the setting does not exist": that is a claim about the SERVER, and a
     * restricted reading cannot make it. What it can say is that it was not allowed to look, which
     * is the difference between a dead end and something a reader can fix.
     */
    public function absenceReason(): ?UndeterminedReason
    {
        return $this->sawEverything === false ? UndeterminedReason::MissingPrivilege : $this->failure;
    }

    /** One setting by name, or null when the reading does not carry it. */
    public function get(string $name): ?Setting
    {
        return $this->settings[$name] ?? null;
    }
}
