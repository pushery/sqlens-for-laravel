<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Catalog\Statistics\Estimate;
use Pushery\SQLens\Catalog\Statistics\EstimateFreshness;
use Pushery\SQLens\ShippedLocale;

/**
 * A statistics number in the reader's language, with the marker that says what it is worth.
 *
 * ## Why this is not `Estimate::describe()`
 *
 * That method exists and stays: it is the STABLE rendering, the one two readings of an unchanged
 * database diff cleanly against and the one a hash is taken over. Translating it would mean the same
 * database produced a different digest on a German machine than on an English one — drift where
 * nothing moved.
 *
 * So there are two renderings of one fact, and the split is the point rather than duplication: the
 * machine reads the stable one, the person reads this. They may never be the same string, because
 * they answer to different requirements — one must never change, the other must change with the
 * reader.
 *
 * ## Why it is one class rather than a call at each site
 *
 * The marker has to be impossible to forget. A reporter that formatted a number itself would be one
 * `sprintf` away from printing `4200000` with nothing beside it, and the reader would take a guess
 * for a count. Every user-facing rendering of an estimate goes through here, so a new output surface
 * inherits the marker instead of having to remember it.
 *
 * ## What is NOT translated, deliberately
 *
 * The unit and the source keep their English identifiers. They are public API from 1.0 on — a
 * consumer matching on `row_count` must keep matching on it whatever language the report is read in,
 * and a translated source name would be a breaking change once per language.
 */
final readonly class EstimateNarrator
{
    public function __construct(private Translator $translator) {}

    /** The number, its unit and source, and what the number is worth — in the reader's language. */
    public function narrate(Estimate $estimate): string
    {
        return sprintf(
            '%d %s (%s, %s, %s)',
            $estimate->value,
            // Untranslated on purpose: identifiers, not prose.
            $estimate->unit()->value,
            $this->line($estimate->isExact() ? 'exact' : 'estimated'),
            $estimate->source->value,
            $this->freshness($estimate),
        );
    }

    /**
     * How old the statistics behind a number are — as a TIMESTAMP, never as "x minutes ago".
     *
     * A relative age is read against the wall clock, so the same reading rendered twice produces two
     * different sentences and a report stops being reproducible. The moment is normalized to UTC for
     * the same reason: one moment, one string, whatever timezone the session carries.
     */
    private function freshness(Estimate $estimate): string
    {
        $measuredAt = $estimate->measuredAt;

        return match ($estimate->freshness) {
            EstimateFreshness::Measured => $measuredAt instanceof DateTimeImmutable
                ? $this->line('measured_at', [
                    'timestamp' => $measuredAt->setTimezone(new DateTimeZone('UTC'))->format(DateTimeInterface::ATOM),
                ])
                : $this->line('age_unknown'),
            EstimateFreshness::NeverCollected => $this->line('never_collected'),
            EstimateFreshness::Unknown => $this->line('age_unknown'),
            EstimateFreshness::NotApplicable => $this->line('exact'),
        };
    }

    /** @param  array<string, string>  $replace */
    private function line(string $key, array $replace = []): string
    {
        $translated = $this->translator->get('sqlens::messages.catalog.estimate.'.$key, $replace, ShippedLocale::CODE);

        return is_string($translated) ? $translated : $key;
    }
}
