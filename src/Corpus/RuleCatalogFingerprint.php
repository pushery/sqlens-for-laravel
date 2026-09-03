<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * A digest of WHICH rules a build ships — the thing a false-positive rate is a statement about.
 *
 * ## Why a rate needs one
 *
 * "3.1% false positives" is a claim about a set of rules. Published beside a catalog that has since
 * gained six rules, it is a number about a package that no longer exists — and it reads as current,
 * because nothing in the file says otherwise. The most likely direction of that error is the
 * flattering one: new rules are the ones nobody has measured yet.
 *
 * ## Ids only, sorted
 *
 * Not the rules' metadata, and that is deliberate. A rule whose SEVERITY changed has not changed
 * what it fires on, and re-measuring a whole corpus because somebody moved a rule from medium to
 * high would make the gate expensive enough to be switched off. What changes a false-positive rate
 * is a rule appearing, disappearing, or changing what it matches — and the first two are exactly
 * what this catches.
 *
 * The third is not catchable this way, and saying so is the point: a rule whose PREDICATE changed
 * under the same id produces the same fingerprint. That is a limit of the mechanism, not a gap to
 * be closed by hashing more fields — hashing the metadata would fire on changes that cannot affect
 * the rate, and the gate would be re-run for nothing until somebody stopped believing it.
 */
final readonly class RuleCatalogFingerprint
{
    /**
     * @param  list<string>  $ruleIds
     */
    public static function of(array $ruleIds): string
    {
        sort($ruleIds, SORT_STRING);

        return substr(hash('xxh128', implode("\n", array_values(array_unique($ruleIds)))), 0, 16);
    }
}
