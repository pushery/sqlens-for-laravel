<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * A stored routine, described by what it runs AS rather than by what it does.
 *
 * ## Why the body is not here, and never will be
 *
 * `pg_proc.prosrc` is the routine's source. It is the single most likely place in a catalog to hold a
 * credential — an API key a migration pasted in, a connection string for an FDW, a password a trigger
 * uses to reach another system. This package reads catalogs to judge posture, not to copy code, and a
 * body in a PHP variable is a body a stack trace, a var-dump or a JSON report can carry.
 *
 * So the reading takes the four facts the security question actually turns on and leaves the rest on
 * the server. This is the same line `pg_authid.rolpassword` and `pg_hba_file_rules.options` are on.
 *
 * ## The question a routine poses
 *
 * A `SECURITY DEFINER` routine runs with the privileges of its OWNER rather than its caller. That is a
 * deliberate, legitimate and common construction — it is how a low-privilege application is given one
 * narrow, audited path into something it otherwise could not touch.
 *
 * It becomes a privilege escalation the moment the routine's `search_path` is not pinned. PostgreSQL
 * resolves unqualified names through the CALLER's `search_path`, so a caller who can create a schema
 * ahead of the routine's own can substitute their own `public.now()` — and the routine will call it,
 * as the owner. `EXECUTE` on such a routine is therefore not "may run this function"; it is "may run
 * arbitrary code as the owner".
 *
 * The distinction is exactly what `settings` carries, and it is why the two states are separate
 * findings rather than one: one is a design to be aware of, the other is a hole.
 */
final readonly class RoutineObject
{
    /**
     * @param  list<string>  $settings  the routine's own `SET` clauses, as `key=value` — never its body
     */
    private function __construct(
        public string $schema,
        public string $name,
        /** The account whose privileges a `SECURITY DEFINER` routine runs with. */
        public string $owner,
        /** Whether it runs as its OWNER (`SECURITY DEFINER`) rather than as its caller. */
        public bool $definer,
        public array $settings,
        /**
         * Whether this ENGINE lets a routine pin the namespace its unqualified names resolve in.
         *
         * PostgreSQL does, through the routine's own `SET search_path`. MySQL does not — it has no
         * per-routine search path at all, and resolves an unqualified name against the routine's own
         * database. So on MySQL the question the escalation rule asks is not merely unanswered, it does
         * not APPLY, and an empty settings list there means "no such concept" rather than "not pinned".
         *
         * Carried as data rather than checked in the rule, on the same terms as `HbaReading::supported`:
         * a rule that had to know which engine it was looking at is a rule somebody can forget to
         * update. Getting this wrong is not theoretical — without it, every SECURITY DEFINER routine on
         * every MySQL server draws a `critical` finding whose advice names a clause that engine has
         * never had.
         */
        public bool $pathConfigurable,
        public Readability $readability,
    ) {}

    /**
     * @param  list<string>  $settings
     */
    public static function of(
        string $schema,
        string $name,
        string $owner,
        bool $definer,
        Readability $readability,
        array $settings = [],
        bool $pathConfigurable = true,
    ): self {
        return new self(
            trim($schema),
            trim($name),
            trim($owner),
            $definer,
            array_values(array_filter(array_map(trim(...), $settings), static fn (string $s): bool => $s !== '')),
            $pathConfigurable,
            $readability,
        );
    }

    /** How a finding names it: schema-qualified, the way somebody would go and look for it. */
    public function identity(): string
    {
        return $this->schema === '' ? $this->name : $this->schema.'.'.$this->name;
    }

    /**
     * Whether the routine pins its own `search_path`.
     *
     * The presence of the setting is the whole test, and deliberately not its VALUE. PostgreSQL's own
     * guidance is to set it, and the safe values are several — `pg_catalog`, an explicit schema list,
     * or the empty string, which forces every name to be qualified. Judging the value would mean
     * maintaining a list of what counts as safe, and being wrong about the first arrangement nobody
     * thought of. What is unambiguous is the absence: a `SECURITY DEFINER` routine with no pinned path
     * resolves unqualified names through the CALLER's, and that is the exploitable shape.
     */
    public function pinsSearchPath(): bool
    {
        return array_any($this->settings, fn (string $setting): bool => str_starts_with(strtolower($setting), 'search_path='));
    }
}
