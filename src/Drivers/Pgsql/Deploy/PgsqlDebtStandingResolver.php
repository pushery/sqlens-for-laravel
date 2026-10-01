<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\CanonicalName;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;
use Pushery\SQLens\Deploy\DebtEntry;
use Pushery\SQLens\Deploy\DebtStanding;
use Pushery\SQLens\Remediation\ExpandContractTemplate;
use Throwable;

/**
 * Where a recorded debt stands on a live PostgreSQL, in the two questions that make up the answer.
 *
 * ## The division of labor, and why it is not negotiable
 *
 * This class never asks whether a constraint is validated or an index is valid. Those columns have
 * exactly one reader each — {@see NotValidConstraintCheck} and {@see InvalidIndexCheck} — and a
 * second one is the same database answering differently depending on which command asked, which
 * this package treats as a defect rather than an inconsistency. The run has already asked them; the
 * objects they reported arrive here as a list.
 *
 * What is left is the question nobody has asked yet: **does the object exist at all?** That is what
 * separates "somebody finished the job" from "the table was dropped, or lives in a schema this run
 * never looked at, or belongs to a role that cannot see it" — and those must never collapse, because
 * collapsing them removes a ledger entry on the strength of an absence.
 *
 * ## Read-only, on the session it was handed
 *
 * Catalog views only, inside the session bounds the caller established. It takes no lock of its own
 * and opens no connection of its own: a second session against the same instance is the harm the
 * whole reader design exists to prevent.
 */
final readonly class PgsqlDebtStandingResolver implements ResolvesDebtStanding
{
    /**
     * @param  list<string>  $stillOwed  the canonical object names this run's checks reported as
     *                                   still carrying their debt — the ONE reading of those
     *                                   catalog columns, taken by the classes that own them
     */
    public function __construct(
        private array $stillOwed,
        private ReaderSession $session,
    ) {}

    public function standingFor(DebtEntry $entry): DebtStanding
    {
        // Reported again by the check that owns the column: nothing further to establish.
        if (in_array($entry->object, $this->stillOwed, true)) {
            return DebtStanding::StillOpen;
        }

        return $entry->kind === ExpandContractTemplate::DEBT_KIND
            ? $this->expandStanding($entry)
            : $this->existenceStanding($entry);
    }

    /**
     * Where an expand without its contract stands.
     *
     * The account records the column that was ADDED, the object the rule's finding names, and it
     * records it without its table: the rule qualifies the column through the schema of its table
     * when the statement named one, and never with the table itself. The column it replaces is in
     * no field of the entry either. So the catalog answers one thing, whether a table still carries
     * a column of that name. When one does, nothing here says whether the replaced column is gone,
     * and the question stays open. When none does, the object is not found, which is not the same
     * as settled: an added column renamed onto the old name and a dropped table look alike here.
     *
     * A bare name is matched across the schemas a user's tables live in and never the server's own,
     * where a column called `description` exists in every database.
     */
    #[RawSql(reason: 'asks the catalog whether a table still carries the column an expand debt recorded')]
    private function expandStanding(DebtEntry $entry): DebtStanding
    {
        $parts = array_map(CanonicalName::bare(...), $this->nameParts($entry->object));

        if (count($parts) > 2) {
            return DebtStanding::Unaskable;
        }

        [$schema, $column] = count($parts) === 2 ? $parts : [null, $parts[0]];
        $scope = $schema === null ? '' : ' and n.nspname = ?';

        try {
            $rows = $this->session->read(static fn (Connection $db): array => $db->select(
                'select 1 from pg_attribute a'
                .' join pg_class t on t.oid = a.attrelid'
                .' join pg_namespace n on n.oid = t.relnamespace'
                .' where a.attname = ? and a.attnum > 0 and not a.attisdropped'
                .' and t.relkind in (\'r\', \'p\', \'f\')'
                .' and n.nspname not in (\'pg_catalog\', \'information_schema\')'
                .' and n.nspname not like \'pg_toast%\' and n.nspname not like \'pg_temp%\''
                .$scope.' limit 1',
                $schema === null ? [$column] : [$column, $schema],
            ));
        } catch (Throwable) {
            return DebtStanding::Unreadable;
        }

        return $rows !== [] ? DebtStanding::Unaskable : DebtStanding::ObjectNotFound;
    }

    /**
     * A canonical name split at the dots that separate its parts, never at a dot inside quotes.
     *
     * @return list<string>
     */
    private function nameParts(string $name): array
    {
        return preg_split('/\.(?=(?:[^"]*"[^"]*")*[^"]*$)/', $name) ?: [$name];
    }

    /**
     * Where a debt stands that is settled by its object being there: the object present and not
     * reported again by the check that owns it is a paid debt, and an absent one is an open question.
     *
     * The name may be schema-qualified or bare, because a debt recorded from a migration carries
     * only what the statement said. Both spellings are matched, and a bare one deliberately matches
     * across schemas: reporting "not found" for an object that is right there under a schema the
     * migration never named would send somebody looking for a table that exists.
     */
    #[RawSql(reason: 'asks the catalog whether the object a ledger entry names is still there, so a settled debt is settled rather than merely unreadable')]
    private function existenceStanding(DebtEntry $entry): DebtStanding
    {
        [$schema, $name] = str_contains($entry->object, '.')
            ? explode('.', $entry->object, 2)
            : [null, $entry->object];

        // The schema clause is composed rather than bound as a nullable parameter, and that cost a
        // measurement: `? is null` leaves PostgreSQL unable to determine the parameter's type, the
        // statement throws, and the catch below turns a perfectly findable object into "not found".
        // A guard that fails closed is right; one that fails closed for a reason that has nothing
        // to do with the question is a silent wrong answer.
        $scope = $schema === null ? '' : ' and n.nspname = ?';
        $bindings = $schema === null ? [$name] : [$name, $schema];

        $sql = match ($entry->kind) {
            'not_valid_constraint' => 'select 1 from pg_constraint c'
                .' join pg_class t on t.oid = c.conrelid'
                .' join pg_namespace n on n.oid = t.relnamespace'
                .' where c.conname = ?'.$scope.' limit 1',
            'invalid_index' => 'select 1 from pg_class c'
                .' join pg_namespace n on n.oid = c.relnamespace'
                .' where c.relname = ? and c.relkind = \'i\''.$scope.' limit 1',
            default => null,
        };

        // A kind this build has no catalog question for. Answering "gone" would remove the entry;
        // answering "still owed" would report a debt nobody can see. Neither is honest, so the
        // question stays open and says why, without claiming the object is missing.
        if ($sql === null) {
            return DebtStanding::Unaskable;
        }

        try {
            $rows = $this->session->read(
                static fn (Connection $db): array => $db->select($sql, $bindings),
            );
        } catch (Throwable) {
            // NOT resolved, and not an absence either: a privilege the role lacks and a debt
            // somebody paid look identical from here.
            return DebtStanding::Unreadable;
        }

        return $rows !== [] ? DebtStanding::Resolved : DebtStanding::ObjectNotFound;
    }
}
