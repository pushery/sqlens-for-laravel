<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Facts measured beside the settings, so a rule about a variable can name what it already affects.
 *
 * ## Why this is one collaborator and not five
 *
 * Five server-baseline rules need the same shape: a setting, plus something counted or listed from
 * the catalog that makes the setting concrete — the tables still on a legacy row format, the columns
 * that already rewrite themselves on update, whether the timezone tables are populated. Each of the
 * five specs invented its own attribute naming and its own way of telling "measured zero" from
 * "could not measure", and five conventions is five chances for one of them to collapse the two.
 *
 * So the fact travels as a triple — value, {@see CrossFactState}, and a reason when it is missing.
 *
 * This class only COLLECTS and FLATTENS. A rule never holds one: the triple reaches it through the
 * subject, via the base's `crossFact()` / `crossFactState()` pair. Read accessors here would be a
 * second way to ask the same question, and the two would eventually disagree about what an absent
 * fact means — which is the one thing this type exists to keep unambiguous.
 *
 * ## What a driver collector must guarantee
 *
 * That the state is never guessed from the value. An empty list with `Measured` and an empty list
 * with `Unavailable` are the same bytes and opposite claims; only the collector, which knows whether
 * its query ran, can say which happened. A collector that returns `None` because a query threw is
 * the exact defect this type is built to make impossible to write by accident.
 */
final readonly class SettingCrossFacts
{
    /**
     * The accounts holding `FILE`, measured beside `local_infile`.
     *
     * The one fact name that lives HERE rather than on the collector that produces it, and the
     * asymmetry is the point rather than an oversight. Every other name is read by a rule in the
     * same driver namespace as its collector, so the constant can sit with the query. This one is
     * read by a rule in the CORE namespace, which may not name a driver — the split is mechanical
     * and enforced. A name is a contract between a reader and a rule, so when the two live on
     * opposite sides of that line, the contract belongs to neither and goes in the vocabulary both
     * already share.
     */
    public const string FILE_PRIVILEGE_ACCOUNTS = 'file_privilege_accounts';

    /**
     * Whether this server offers TLS at all, measured beside `ssl_min_protocol_version`.
     *
     * Here for the same reason as the name above: the rule that reads it lives in the CORE namespace,
     * which may not name a driver, while the collector that produces it is driver-specific.
     *
     * The fact answers a question the judged value cannot. `ssl_min_protocol_version` keeps its
     * configured value when `ssl` is off — measured on 18.4, where `ssl = off` and the minimum still
     * reads `TLSv1.2` — so a server with TLS switched off entirely can still carry a minimum below
     * the floor. Reporting that would be a second alarm about a capability that is not running, next
     * to the finding that says so, and two findings for one fact is how a report stops being read.
     */
    public const string TLS_OFFERED = 'tls_offered';

    /**
     * Keyed by VARIABLE first, then by fact name.
     *
     * The variable dimension is not bookkeeping. A reading carries several hundred settings, and a
     * flat fact map would hang every fact on every one of them — six hundred subjects each carrying
     * a column list that belongs to one of them. Keyed by variable, a subject carries only what is
     * about it, and a rule cannot accidentally read a fact measured for a different setting.
     *
     * @param  array<string, array<string, array{value: string|null, state: CrossFactState, reason: UndeterminedReason|null, detail: string|null}>>  $facts
     */
    public function __construct(private array $facts = []) {}

    /**
     * No facts were collected at all — the ordinary case for a driver that collects none.
     *
     * Kept beside the public constructor because `SettingCrossFacts::none()` says at a call site
     * what `new SettingCrossFacts` only implies, and the difference matters where the argument is
     * a deliberate "this driver measures nothing yet" rather than an oversight.
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * A fact the collector measured, with its value.
     *
     * `$value` null means the query ran and found nothing; that is {@see CrossFactState::None} and it
     * is an answer. It is emphatically not the same as never having asked.
     */
    public function withMeasured(string $variable, string $name, ?string $value): self
    {
        return $this->with($variable, $name, [
            'value' => $value,
            'state' => $value === null || $value === '' ? CrossFactState::None : CrossFactState::Measured,
            'reason' => null,
            'detail' => null,
        ]);
    }

    /**
     * A fact the collector could NOT measure, with the reason it could not.
     *
     * The reason is required rather than optional: a rule turns this into an `undetermined` finding
     * and an undetermined without a named reason is not constructible anywhere else in this package.
     */
    public function withUnavailable(string $variable, string $name, UndeterminedReason $reason, ?string $detail = null): self
    {
        return $this->with($variable, $name, [
            'value' => null,
            'state' => CrossFactState::Unavailable,
            'reason' => $reason,
            'detail' => $detail,
        ]);
    }

    /** @param  array{value: string|null, state: CrossFactState, reason: UndeterminedReason|null, detail: string|null}  $fact */
    private function with(string $variable, string $name, array $fact): self
    {
        $facts = $this->facts;
        $facts[$variable] = [...($facts[$variable] ?? []), $name => $fact];

        return new self($facts);
    }

    /**
     * What kind of answer a fact on this subject is — the read side of the same key convention.
     *
     * Static and here rather than on each base, because the flattening above and this reading are
     * one convention seen from two ends. They lived apart for exactly one rule and immediately
     * diverged into two copies of the same `tryFrom ?? Unavailable` — which is the drift this whole
     * type exists to prevent, arriving inside the type itself.
     *
     * A subject carrying no state at all reads as {@see CrossFactState::Unavailable}: the cautious
     * direction, and a real case rather than a defensive one — a driver that collects no facts
     * produces exactly that, and a rule needing one must then report it could not check.
     */
    public static function stateOn(SchemaObject $object, string $name): CrossFactState
    {
        return CrossFactState::tryFrom((string) $object->getString($name.'_state')) ?? CrossFactState::Unavailable;
    }

    /**
     * The attributes to hang on a setting subject, flattened.
     *
     * Flattened rather than nested because {@see SchemaObject} carries
     * scalars — and the flattening is done HERE, once, so the five rules that read these never agree
     * on a key by coincidence.
     *
     * @return array<string, scalar|null>
     */
    public function attributesFor(string $variable): array
    {
        $attributes = [];

        foreach ($this->facts[$variable] ?? [] as $name => $fact) {
            $attributes[$name] = $fact['value'];
            $attributes[$name.'_state'] = $fact['state']->value;
            $attributes[$name.'_reason'] = $fact['reason']?->value;
            $attributes[$name.'_detail'] = $fact['detail'];
        }

        return $attributes;
    }
}
