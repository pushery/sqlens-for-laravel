<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * Where the VALUES in a statement came from — the file, or somewhere outside it.
 *
 * A rule about secrets needs this and cannot get it from the SQL. By the time a statement reaches a
 * rule its values are literals either way: `PASSWORD ?` with a binding and `PASSWORD 'hunter2'`
 * typed into the migration arrive as the same canonical text. Without this marker a rule that
 * reports the second necessarily reports the first — which is the shape it RECOMMENDS, so following
 * its own advice produces the finding again. Measured on this tree; the fixture pair proved it.
 *
 * ## Why this can be answered at all
 *
 * Not by re-reading the SQL, and not by tracking byte ranges through the substitution. The captor
 * already holds the two facts this needs: how many placeholders the statement had, and how many
 * bindings arrived with it. `BindingSubstitutor` compares them today to decide whether it has work
 * to do; the same comparison, written down instead of discarded, is the marker.
 *
 * The case that makes it work is the SIMPLE one: **no bindings at all** means every literal in the
 * text was typed into the file. That is the only statement this needs to make with certainty, and
 * it is the one a secrets rule acts on.
 *
 * ## What it deliberately does NOT claim
 *
 * {@see self::AllValuesBound} does not mean every value is bound. A statement can carry a binding
 * AND a hard-coded literal — `… PASSWORD 'x' … WHERE id = ?` — and this marker reports the binding.
 * A rule reading it then stays quiet about a real literal.
 *
 * That is the chosen direction to be wrong in, and the asymmetry is the whole argument: a false
 * alarm on the shape a rule RECOMMENDS costs the entire id, because somebody silences it and takes
 * the true findings with it. A missed find in a mixed statement costs one find. Narrowing it needs
 * the byte ranges this design deliberately does not build, and a rule relying on this marker owes
 * the limitation in its own `limitations()`.
 */
enum ValueOrigin: string
{
    /**
     * No bindings arrived, so every literal in the statement text was written there.
     *
     * The only certainty in this enum, and the one a secrets rule acts on.
     */
    case LiteralsInText = 'literals_in_text';

    /**
     * Bindings arrived: at least one value in this statement came from outside the file.
     *
     * Which position held which is not recoverable — Laravel's pretend log inlines them before the
     * capture layer sees the statement at all. What is recoverable is the restraint: a rule must not
     * claim a literal here.
     */
    case AllValuesBound = 'all_values_bound';

    /**
     * The binding information never reached the captor.
     *
     * A statement judged without the call that produced it. Neither of the answers above is
     * available, and a rule that needs this says so with a named undetermined rather than guessing.
     */
    case Undeterminable = 'undeterminable';

    /**
     * Classify one captured statement from the two facts the captor already has.
     *
     * `$bindings` is the array Laravel handed the query log. `null` is the absence of the
     * information — genuinely different from an empty array, which is the positive statement "this
     * call had no bindings" and is exactly what makes {@see self::LiteralsInText} certain.
     *
     * @param  list<mixed>|null  $bindings
     */
    public static function of(?array $bindings): self
    {
        return match (true) {
            $bindings === null => self::Undeterminable,
            $bindings === [] => self::LiteralsInText,
            default => self::AllValuesBound,
        };
    }
}
