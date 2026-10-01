<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Rules\Suite;

/**
 * Which baseline entries one run can judge.
 *
 * The lint suite and the audit suite read the same baseline, and a run can match only the entries
 * of findings it produces. `sqlens:audit` used to treat every entry as its own, so each entry
 * `sqlens:baseline` wrote for the migrations was stale on every audit, and under
 * `sqlens.baseline.stale = error` every audit ended on a misconfiguration over a database that had
 * not changed. The lint suite did the same to catalog entries. An entry this run cannot judge is
 * neither stale nor unverifiable here; a run that asks for it will judge it.
 *
 * Three facts decide it, and an entry is this run's only when none of them rules it out. Its `kind`
 * says what the finding was about, and each suite fails findings of its own kinds: the audit about
 * catalog objects, the lint suite about migrations and call sites. That is what tells the suites
 * apart for a rule that answers in both. Its rule says whether this run asked: a rule that answers
 * only in another suite could not have produced the entry here, and neither could one the run's
 * own gates left out. A run narrowed by level, category or stability, such as `sqlens:security`,
 * applies a part of the suite, and the entries of the rest are not gone because nobody looked for
 * them. And a run that read only some of the migrations cannot say anything about the others: a
 * migration that already ran is not pending, and `--file` reads the files it is given. Only a
 * migration the project no longer has is settled without reading it, because no run will.
 */
final readonly class BaselineScope
{
    /**
     * @param  list<LocationKind>  $kinds  empty means every kind
     * @param  list<string>  $unasked  the rule ids this run did not ask
     * @param  list<string>  $unread  the migrations the project has and this run did not read, by name
     */
    private function __construct(private array $kinds, private array $unasked, private array $unread) {}

    /** Every entry is this run's to judge — for a resolver that belongs to no suite. */
    public static function everything(): self
    {
        return new self([], [], []);
    }

    /**
     * @param  iterable<Rule>  $rules  every rule the run could know about, across drivers and suites
     * @param  list<LocationKind>  $kinds  what this suite's findings are about
     * @param  iterable<Rule>|null  $asked  the rules this run applied once its gates had spoken; null
     *                                      when it applied every rule of its suite
     */
    public static function of(Suite $suite, iterable $rules, array $kinds, ?iterable $asked = null): self
    {
        $askedIds = null;

        if ($asked !== null) {
            $askedIds = [];

            foreach ($asked as $rule) {
                $askedIds[] = $rule->id();
            }
        }

        $unasked = [];

        foreach ($rules as $rule) {
            if (! in_array($suite, $rule->suites(), true) || ($askedIds !== null && ! in_array($rule->id(), $askedIds, true))) {
                $unasked[] = $rule->id();
            }
        }

        return new self($kinds, array_values(array_unique($unasked)), []);
    }

    /**
     * The same scope, leaving out entries under these ids as well.
     *
     * For ids no registry carries: an external tool's findings pass the run's level like a rule's
     * do, so an entry under one of its ids above the level was not asked either.
     *
     * @param  list<string>  $ids
     */
    public function without(array $ids): self
    {
        return new self($this->kinds, array_values(array_unique([...$this->unasked, ...$ids])), $this->unread);
    }

    /**
     * The same scope for a run that read these migrations of the ones the project has.
     *
     * An entry about a migration the project has and the run did not read is left alone, because the
     * run never read the file its finding is in. An entry about a migration the project no longer has
     * is still judged.
     *
     * @param  list<string>  $read  by name, which is what an entry about a migration carries as its subject
     * @param  list<string>  $existing  every migration the project has, by name
     */
    public function readingOnly(array $read, array $existing): self
    {
        return new self($this->kinds, $this->unasked, array_values(array_diff(array_unique($existing), $read)));
    }

    public function judges(BaselineEntry $entry): bool
    {
        return ! in_array($entry->ruleId, $this->unasked, true)
            && ($this->kinds === [] || in_array($entry->kind, $this->kinds, true))
            && ($entry->kind !== LocationKind::Migration || ! in_array($entry->subject, $this->unread, true));
    }
}
