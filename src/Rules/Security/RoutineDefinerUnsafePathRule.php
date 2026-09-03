<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A definer routine that pins a search path — to somewhere somebody else can write.
 *
 * The sibling rule asks whether a `SET search_path` clause exists. This one asks what is IN it, and
 * the two are not the same question: a routine with `SET search_path = public` passes the first and
 * is exactly as exploitable as one with no clause at all, the moment `public` is writable by anyone
 * else. That was PostgreSQL's own default before 15, and on a database that grew through those
 * versions it usually still is.
 *
 * ## Why this can be measured rather than opined about
 *
 * The obvious objection to judging the VALUE is that it means keeping a list of what counts as a
 * safe path — and being wrong about the first arrangement nobody thought of. That objection answers
 * a question this rule does not ask.
 *
 * It asks the catalog: for each schema in the routine's own path, may anybody other than the
 * routine's OWNER create objects there? `pg_namespace.nspacl` answers it, the grant reading already
 * carries it, and the answer is a fact about this server rather than an opinion about path hygiene.
 * A path of `pg_catalog`, or a schema only its owner may write to, produces nothing.
 *
 * ## `pg_temp` is the second way, and it needs no grant at all
 *
 * The caller's own temporary schema belongs at the END of a path or not in it. Anywhere earlier, the
 * caller creates a function there and the routine resolves to it — the same substitution, reached
 * without anyone granting the attacker anything.
 *
 * ## Why `medium` rather than the sibling's `critical`
 *
 * Both end in code running as the owner, but this one takes a second condition that the operator can
 * see and change: somebody else holds `CREATE` on a schema in the path. The unpinned case needs no
 * such grant — any caller who can make a schema is already there. Severity is metadata on the RULE
 * in this package, so the two weights are necessarily two ids rather than one rule reading its own
 * subject twice.
 */
final class RoutineDefinerUnsafePathRule extends AbstractRoutineRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROUTINE_DEFINER_UNSAFE_PATH';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** The pinned half — this rule is about paths that exist and are still not enough. */
    protected function appliesToPinnedPath(): bool
    {
        return true;
    }

    /**
     * Silent unless the measurement found something, which is most routines.
     *
     * The base class hands every pinned definer routine to both pinned-path rules; the inventory
     * rule reports each one at `low`, and this one speaks only where the path is measurably open.
     */
    #[Override]
    protected function appliesToSubject(SchemaObject $object): bool
    {
        if ($this->writableSchemas($object) !== []) {
            return true;
        }

        return $object->getBool('pg_temp_not_last') === true;
    }

    protected function message(SchemaObject $object): string
    {
        $owner = $object->getString('owner') ?? 'its owner';
        $writable = $this->writableSchemas($object);

        if ($writable !== []) {
            return sprintf(
                '%s runs as %s and pins its search_path, but %s in that path %s somebody other than %s may '
                .'create objects in. That is the same substitution the unpinned case allows: a role with '
                .'CREATE there defines a function with the name this routine uses unqualified, and the '
                .'routine calls it as %s. Point the path at a schema only %s can write to, at the catalog '
                .'schema, or at the empty string to force every name to be qualified — or revoke CREATE '
                .'from the schema, whichever fits the application.',
                $object->qualifiedName,
                $owner,
                implode(', ', $writable),
                count($writable) === 1 ? 'is a schema' : 'are schemas',
                $owner,
                $owner,
                $owner,
            );
        }

        return sprintf(
            '%s runs as %s and pins its search_path, but pg_temp appears in that path before the end. '
            .'pg_temp is the CALLER\'s own schema: a caller creates a function there and this routine '
            .'resolves to it before reaching the schema it meant, and runs it as %s — the same '
            .'substitution, reached without anyone granting the caller anything. Move pg_temp to the end '
            .'of the path, or leave it out.',
            $object->qualifiedName,
            $owner,
            $owner,
        );
    }

    /**
     * The schemas in this routine's path somebody other than its owner may create in.
     *
     * Read from the subject, never re-derived: it is stamped once in SecuritySubjects from the grant
     * reading, so this rule and any later one see the same answer.
     *
     * @return list<string>
     */
    private function writableSchemas(SchemaObject $object): array
    {
        $stamped = $object->getString('path_schemas_others_may_create_in') ?? '';

        return array_values(array_filter(explode(',', $stamped), static fn (string $s): bool => $s !== ''));
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the routine\'s SIGNATURE and its declared path, never its body. A routine whose every reference is already schema-qualified is safe in practice and is still reported, because whether the next edit stays qualified is not something the catalog can promise',
            'judges who can WRITE to the schemas the path names, from the catalog\'s grants. A schema writable through a role membership rather than a direct grant is not seen here',
        ];
    }
}
