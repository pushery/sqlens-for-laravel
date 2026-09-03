<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * One row-level security policy, in the form a rule can judge.
 *
 * ## The expression is PostgreSQL's own deparse, not our normalization
 *
 * `pg_get_expr()` rebuilds the stored parse tree as text, so `USING ( TRUE )`, `using(true)` and
 * `USING (TRUE)` all come back as `true` — measured on PostgreSQL 18. That matters more than it
 * sounds: the canonicalization this package insists on everywhere is exactly what a rule would otherwise fake with
 * a regex over whatever somebody typed, and the server does it correctly by construction because it
 * is printing the tree it will actually evaluate.
 *
 * So a rule about "a policy that lets everything through" compares against `true` and is right, rather
 * than matching a spelling and being right by luck.
 */
final readonly class RlsPolicy
{
    /** The grantee PostgreSQL writes as role oid 0 — the same pseudo-role a grant names. */
    public const string PUBLIC_ROLE = 'PUBLIC';

    /**
     * @param  list<string>  $roles  the roles this policy applies to, sorted; `['PUBLIC']` when it
     *                               applies to every role
     */
    private function __construct(
        public string $name,
        public RlsCommand $command,
        /** Permissive policies are OR-ed together; a restrictive one is AND-ed and can only narrow. */
        public bool $permissive,
        public array $roles,
        /** The row filter, as the server deparses it. Null when the policy has none. */
        public ?string $using,
        /** The write check, deparsed. Null when the policy sets none. */
        public ?string $withCheck,
    ) {}

    /**
     * @param  list<string>  $roles
     */
    public static function of(
        string $name,
        RlsCommand $command,
        bool $permissive,
        array $roles,
        ?string $using = null,
        ?string $withCheck = null,
    ): self {
        $sorted = array_values(array_unique(array_map(trim(...), $roles)));
        sort($sorted);

        return new self(
            trim($name),
            $command,
            $permissive,
            $sorted === [] ? [self::PUBLIC_ROLE] : $sorted,
            self::expression($using),
            self::expression($withCheck),
        );
    }

    /**
     * The expressions the server deparses an always-true filter into.
     *
     * MEASURED against PostgreSQL 18.4 rather than reasoned about, because the folding is not uniform:
     * `USING ( TRUE )`, `USING ((true))` and `USING ('t'::bool)` all come back as `true`, but
     * `USING (1 = 1)` comes back as `(1 = 1)` — the server keeps the comparison. A rule comparing
     * against `true` alone would miss the second form entirely.
     *
     * Deliberately a short, exact list rather than an expression evaluator. That is the honesty
     * boundary this rule family is built on: a filter SQLens cannot reduce to a constant is one it
     * says nothing about, rather than one it guesses at.
     *
     * @var list<string>
     */
    private const array ALWAYS_TRUE = ['true', '(1 = 1)'];

    /**
     * Whether this policy admits every row it is asked about.
     *
     * A comparison rather than a pattern, because the server has already reduced the spelling — see
     * {@see self::ALWAYS_TRUE} for what it reduces to and what it does not.
     *
     * ## A policy with no `USING` admits NOTHING, and this used to say the opposite
     *
     * The first version of this method answered yes for a null filter, on the reasoning that a missing
     * `USING` means "no restriction". Measured on PostgreSQL 18.4, that is exactly backwards: a table
     * with two rows, RLS enabled and `CREATE POLICY p ON t FOR ALL TO public` — no `USING` at all —
     * shows a reading role ZERO rows. The same table with `USING (true)` shows both.
     *
     * The direction of the error is what made it worth a measurement rather than a reread: it turned a
     * policy that locks everything out into a report saying the protection is ceremonial, which would
     * send somebody to weaken a lock that was working.
     */
    public function admitsEverything(): bool
    {
        return $this->using !== null && in_array($this->using, self::ALWAYS_TRUE, true);
    }

    /**
     * Whether the WRITE path is unchecked while the read path is not.
     *
     * Only an EXPLICIT always-true `WITH CHECK` counts. An omitted one is not a hole: PostgreSQL
     * applies the `USING` expression to the check when no `WITH CHECK` is given, so a policy with a
     * real filter and no check is fully guarded on both paths — and reporting it would be a false
     * positive on the ordinary way people write policies.
     */
    public function checkAdmitsEverything(): bool
    {
        return $this->withCheck !== null && in_array($this->withCheck, self::ALWAYS_TRUE, true);
    }

    /** Whether it reaches every role on the server, present and future. */
    public function appliesToPublic(): bool
    {
        return in_array(self::PUBLIC_ROLE, $this->roles, true);
    }

    /**
     * @return array{name: string, command: string, permissive: bool, roles: list<string>, using: string|null, with_check: string|null}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'command' => $this->command->value,
            'permissive' => $this->permissive,
            'roles' => $this->roles,
            'using' => $this->using,
            'with_check' => $this->withCheck,
        ];
    }

    /** An empty expression is an ABSENT one — the two are the same fact and only one of them reads so. */
    private static function expression(?string $raw): ?string
    {
        $trimmed = trim((string) $raw);

        return $trimmed === '' ? null : $trimmed;
    }
}
