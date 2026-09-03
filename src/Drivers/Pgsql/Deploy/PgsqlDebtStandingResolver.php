<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;
use Pushery\SQLens\Deploy\DebtEntry;
use Pushery\SQLens\Deploy\DebtStanding;
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

        return match ($this->objectExists($entry)) {
            true => DebtStanding::Resolved,
            false => DebtStanding::ObjectNotFound,
            // The catalog could not be read. NOT resolved: a privilege the role lacks and a debt
            // somebody paid look identical from here, and only one of them is good news.
            null => DebtStanding::ObjectNotFound,
        };
    }

    /**
     * Whether the object the entry names is in the catalog at all — true, false, or null when the
     * question could not be put.
     *
     * The name may be schema-qualified or bare, because a debt recorded from a migration carries
     * only what the statement said. Both spellings are matched, and a bare one deliberately matches
     * across schemas: reporting "not found" for an object that is right there under a schema the
     * migration never named would send somebody looking for a table that exists.
     */
    #[RawSql(reason: 'asks the catalog whether the object a ledger entry names is still there, so a settled debt is settled rather than merely unreadable')]
    private function objectExists(DebtEntry $entry): ?bool
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
            // A kind this build has no catalog question for. Answering "gone" would remove the
            // entry; answering "still owed" would report a debt nobody can see. Neither is honest,
            // so the question stays open and says so.
            default => null,
        };

        if ($sql === null) {
            return null;
        }

        try {
            $rows = $this->session->read(
                static fn (Connection $db): array => $db->select($sql, $bindings),
            );
        } catch (Throwable) {
            return null;
        }

        return $rows !== [];
    }
}
