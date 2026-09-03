<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * One line of `pg_hba.conf`, canonicalized.
 *
 * ## Why the file is read through a catalog view and never off disk
 *
 * `pg_hba_file_rules` is the server's own parse of its own file. Reading the file instead would mean
 * re-implementing that parser — including the include directives, the quoting rules and the
 * continuation lines — and then being subtly wrong about a file the server has already understood.
 * It also would not work at all where it matters most: a managed instance does not hand out its
 * filesystem, and the audit connection is a database connection rather than a shell.
 *
 * ## The error column is a finding, not a parse failure
 *
 * A line PostgreSQL could not understand carries `error` and is otherwise empty. That is not a
 * problem with the reading — the server is telling us, in its own words, that one of its
 * authentication rules is broken. A broken line does not authenticate anybody, so the rule that
 * follows it decides who gets in; that is a security fact and it belongs in a report rather than in
 * an exception. Hence `error` is a first-class field here, and {@see self::isBroken()} exists so a
 * rule can say so without string-matching.
 *
 * ## What is deliberately NOT normalized
 *
 * `authMethod` keeps the server's own spelling. The temptation is to fold `md5` and `scram-sha-256`
 * into "password-ish", and it would be wrong in the direction that matters: the whole point of the
 * MD5 rule is that those two are not the same thing. A vocabulary that lost the distinction would
 * make the rule unwritable.
 *
 * ## What is deliberately NOT read
 *
 * The `options` column is never selected. It holds the auth method's parameters, and for `ldap` or
 * `radius` those include a bind password or a shared secret — a credential, sitting in the one
 * column of this view that has one. No rule here needs it: every question the HBA rules ask is
 * about the TYPE, the SCOPE and the METHOD, all of which are separate columns. So it is left on the
 * server, on the same terms as `pg_authid.rolpassword`: a secret in a PHP variable is a secret a
 * stack trace or a var-dump can carry, and the cheapest way to keep it out of one is not to fetch
 * it. A rule that one day genuinely needs an option reads THAT option by name and says why.
 */
final readonly class HbaRule
{
    /**
     * @param  list<string>  $databases  the `database` column, which is a list even when it is one name
     * @param  list<string>  $users  the `user_name` column, same shape
     */
    private function __construct(
        public int $ruleNumber,
        public ?string $fileName,
        public ?int $lineNumber,
        /** `local`, `host`, `hostssl`, `hostnossl`, `hostgssenc`, `hostnogssenc` — or null on a broken line. */
        public ?string $type,
        public array $databases,
        public array $users,
        /** Null for a `local` rule, which has no address by construction. */
        public ?string $address,
        public ?string $netmask,
        public ?string $authMethod,
        /** The server's own complaint about this line, or null when it parsed. */
        public ?string $error,
        public Readability $readability,
    ) {}

    /**
     * @param  list<string>  $databases
     * @param  list<string>  $users
     */
    public static function of(
        int $ruleNumber,
        ?string $type,
        array $databases,
        array $users,
        ?string $authMethod,
        Readability $readability,
        ?string $fileName = null,
        ?int $lineNumber = null,
        ?string $address = null,
        ?string $netmask = null,
        ?string $error = null,
    ): self {
        return new self(
            $ruleNumber,
            self::text($fileName),
            $lineNumber,
            self::text($type),
            array_values(array_filter(array_map(trim(...), $databases), static fn (string $v): bool => $v !== '')),
            array_values(array_filter(array_map(trim(...), $users), static fn (string $v): bool => $v !== '')),
            self::text($address),
            self::text($netmask),
            self::text($authMethod),
            self::text($error),
            $readability,
        );
    }

    /** Whether PostgreSQL itself could not parse this line. */
    public function isBroken(): bool
    {
        return $this->error !== null;
    }

    /**
     * Whether this rule governs connections arriving over the network.
     *
     * `local` is a Unix-domain socket: reaching it already means being on the host, so a `trust` there
     * is a different statement from a `trust` on a TCP rule. Every network rule type starts with
     * `host`, which is PostgreSQL's own naming rather than a list this code has to keep in step with.
     */
    public function isNetwork(): bool
    {
        return $this->type !== null && str_starts_with($this->type, 'host');
    }

    /**
     * Whether this rule accepts connections from the entire address space.
     *
     * The reason this is a method on the object rather than a check inside a rule: `pg_hba.conf`
     * spells the same statement four ways, and the view splits some of them across two columns.
     * `all` arrives as the literal address `all` with no netmask; `0.0.0.0/0` arrives split into the
     * address `0.0.0.0` and the netmask `0.0.0.0`; `0.0.0.0 0.0.0.0` — the long form — arrives
     * identically; `::/0` is the same shape in IPv6. A rule matching on the text would answer
     * differently for four spellings of one fact, which is precisely the guessing the canonicalization
     * layer exists to remove.
     *
     * `samehost` and `samenet` are deliberately NOT open: they are keywords that resolve to the
     * server's own addresses, so they narrow rather than widen.
     */
    public function isOpenToTheWorld(): bool
    {
        if ($this->address === null) {
            return false;
        }

        if ($this->address === 'all') {
            return true;
        }

        // A `/0` prefix straight on the address, for a driver that hands the CIDR over unsplit. The
        // view splits it, so this arm is a guard against a shape we do not currently receive rather
        // than a path taken on PostgreSQL 18.
        if (str_ends_with($this->address, '/0')) {
            return true;
        }

        // An all-zero netmask is what `/0` becomes once the view has split it — the same statement,
        // one column further along.
        return in_array($this->address, ['0.0.0.0', '::'], true)
            && in_array($this->netmask, ['0.0.0.0', '::'], true);
    }

    /** The location a finding points at, as a reader would cite it. */
    public function location(): string
    {
        if ($this->fileName === null || $this->lineNumber === null) {
            return "pg_hba rule {$this->ruleNumber}";
        }

        return "{$this->fileName}:{$this->lineNumber}";
    }

    private static function text(?string $value): ?string
    {
        return $value === null || trim($value) === '' ? null : trim($value);
    }
}
