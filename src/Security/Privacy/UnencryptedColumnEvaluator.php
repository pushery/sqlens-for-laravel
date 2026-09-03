<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Whether one column looks like it holds personal data and is stored in the clear.
 *
 * Driver-neutral, and that is not an accident of convenience: the question is about a COLUMN NAME
 * and an Eloquent cast, and neither is a property of PostgreSQL or MySQL. The spike that preceded
 * this ({@see EncryptedCasts}) measured that server-side
 * encryption cannot be detected from the catalog at all — pgcrypto leaves a `bytea` behind and no
 * record of what put it there — so there is no engine-specific half left to write.
 *
 * ## Three answers, and the middle one is the point
 *
 * - The name matches nothing in the dictionary, or the column is cast to an encrypted type: SILENCE.
 * - The name matches and the model says the column is plain: a FLAG, quiet or quieter.
 * - Anything that stopped the reading from establishing either: UNDETERMINED with the reason named.
 *
 * The third is what makes the first two worth having. Without a model, a column called `iban` is not
 * "fine" — it is unexamined, and a run that reported nothing would be indistinguishable from a run
 * over an application that encrypts everything.
 *
 * ## The honesty limit, stated in the finding itself
 *
 * This reads names. It never reads a value, so it cannot know whether `iban` holds an IBAN or a
 * label for one, and the finding says so in its own text rather than in documentation somebody may
 * not have open. That is also why both severities sit below the CI gate's default: a heuristic that
 * broke a pipeline would be switched off within a week, taking the true positives with it.
 */
final readonly class UnencryptedColumnEvaluator
{
    /**
     * @param  list<string>  $ignoredColumns  qualified names this project has already decided about
     */
    public function __construct(
        private PrivacyDictionary $dictionary,
        private ModelCastReader $models,
        private array $ignoredColumns = [],
    ) {}

    /**
     * The verdict for one column, or null when there is nothing to say about it.
     */
    public function judge(SchemaObject $object): ?RuleVerdict
    {
        if ($object->type !== SchemaObjectType::Column) {
            return null;
        }

        $column = $this->lastSegment($object->qualifiedName);
        $relation = (string) $object->parent;
        $table = $this->lastSegment($relation);

        if ($column === '' || $table === '') {
            return null;
        }

        if ($this->isIgnored($object->qualifiedName, $table.'.'.$column)) {
            return null;
        }

        $signal = $this->dictionary->signalFor($column);

        if ($signal === null) {
            return null;
        }

        $group = (string) $this->dictionary->groupFor($column);
        $protection = $this->models->protectionFor($table, $column);

        // The `instanceof` IS the undetermined test, not a null-check bolted onto one — the same
        // shape RuleVerdict::isUndetermined() uses. A reason that is present or absent cannot
        // express a contradiction, and it narrows the type in the same move.
        if ($protection->reason instanceof UndeterminedReason) {
            return RuleVerdict::undetermined(
                sprintf(
                    '`%s` matches the privacy dictionary (term group `%s`), and whether it is stored '
                    .'encrypted could not be established: %s. This is NOT a clean result — the column '
                    .'was not examined, which reads the same as a column that was and turned out fine.',
                    $object->qualifiedName,
                    $group,
                    $protection->detail === '' ? 'no detail' : $protection->detail,
                ),
                $protection->reason,
            );
        }

        if (! $protection->isReportable()) {
            return null;
        }

        // The LAST gate before a finding, and it is about the column's TYPE rather than the model's
        // casts. A `bytea` or a `blob` is what server-side encryption leaves behind, and it is also
        // what an avatar looks like — measured, nothing in either catalog separates them. So
        // encryption applied at the server may SUPPRESS a finding here and can never raise one.
        if ($this->storesRawBytes($object)) {
            return RuleVerdict::undetermined(
                sprintf(
                    '`%s` matches the privacy dictionary (term group `%s`) and no model casts it, but '
                    .'it stores raw bytes — which is exactly what pgcrypto or an application-level '
                    .'envelope leaves behind. Whether this column is protected cannot be read from a '
                    .'catalog or from a cast, so it is not being called unprotected.',
                    $object->qualifiedName,
                    $group,
                ),
                UndeterminedReason::OpaqueBinaryColumn,
            );
        }

        return RuleVerdict::flag(
            sprintf(
                '`%s` matches the privacy dictionary (term group `%s`) and no Eloquent model casts '
                .'it to an encrypted type, so it is stored in the clear — readable to anyone with '
                .'SELECT on the table, and present in every dump, replica and backup of it. '
                .'THIS IS A NAME HEURISTIC: this package reads column names and never their values, '
                .'so it cannot know whether `%s` holds what its name suggests. If it does not, add '
                .'the qualified name to `sqlens.security.privacy.ignore_columns` and this stops '
                .'asking. If it does, an `encrypted` cast is one line on the model.',
                $object->qualifiedName,
                $group,
                $column,
            ),
            $object->qualifiedName,
            SchemaObjectType::Column,
            // The artifact's call, not the rule's: `iban` means one thing and `religion` is also an
            // ordinary word in a CMS, and the dictionary records which is which precisely so the
            // quieter one can be quieter. Both stay below the gate default.
            $signal === 'strong' ? Severity::Low : Severity::Info,
        );
    }

    /**
     * Both spellings are accepted, because both are what somebody writes.
     *
     * The config asks for a QUALIFIED name so that `notes` on `orders` and `notes` on `patients` stay
     * two decisions. But "qualified" means `orders.notes` to most people and
     * `public.orders.notes` to the catalog, and refusing the shorter one would silently ignore an
     * entry the user believes in — the most expensive kind of green there is.
     */
    private function isIgnored(string $qualified, string $short): bool
    {
        foreach ($this->ignoredColumns as $ignored) {
            $needle = mb_strtolower(trim($ignored));

            if ($needle !== '' && ($needle === mb_strtolower($qualified) || $needle === mb_strtolower($short))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the column's declared type is a raw-byte one on either engine.
     *
     * Matched on a PREFIX rather than a fixed list: MySQL spells four sizes of the same thing
     * (`tinyblob` … `longblob`) and PostgreSQL one, and a list would go stale the first time an
     * engine adds a fifth. `varbinary` and `binary` are the fixed-width relatives and say as little.
     */
    private function storesRawBytes(SchemaObject $object): bool
    {
        $type = mb_strtolower(trim((string) ($object->attributes()['type'] ?? '')));

        return array_any(['bytea', 'blob', 'binary', 'varbinary'], fn (string $binary): bool => $type === $binary || str_ends_with($type, $binary));
    }

    private function lastSegment(string $name): string
    {
        $segments = explode('.', $name);

        return end($segments);
    }
}
