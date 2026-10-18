<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * The database the tool is pointed at, assembled from the connection SQLens was asked to audit.
 *
 * ## Why this is a type rather than four strings
 *
 * The tool has defaults — `localhost:5432/postgres` — and they are the failure this type exists
 * to make impossible. A run that handed the tool three of the four values would get a report about
 * whatever answers on the local machine, alongside core-rule findings about the audited server,
 * and nothing in the output would say the two halves are about different databases. Requiring all
 * four together means an incomplete connection is a named `undetermined` instead.
 *
 * ## Where the password goes, and where it must not
 *
 * Host, port, user and database name travel as arguments. The PASSWORD travels in the child's
 * environment, and only there: an argument list is readable by every user on the machine through
 * `ps`, for as long as the process lives. That is not a theoretical exposure — it is the standard
 * way credentials leak out of tooling, and it costs nothing to avoid.
 *
 * ## The connection's TLS settings go the same way
 *
 * `sslmode`, `sslrootcert`, `sslcert` and `sslkey`, the keys Laravel's PostgreSQL connector hands to
 * the driver, travel as the `PGSSL*` variables the tool's client reads. Without them the tool used
 * its own default, `prefer`: it spoke plaintext to a server that allows it and took any certificate
 * from one that does not, where the application connects with `verify-full`. Measured against a
 * server without TLS, the tool connects with no `PGSSLMODE` and refuses with `require`.
 */
final readonly class PglsConnection
{
    /** What PostgreSQL's own client libraries read a password from. */
    public const string PASSWORD_VARIABLE = 'PGPASSWORD';

    /**
     * The variables the client reads the TLS settings from, by the connection key that carries each.
     *
     * @var array<string, string>
     */
    public const array TLS_VARIABLES = [
        'sslmode' => 'PGSSLMODE',
        'sslrootcert' => 'PGSSLROOTCERT',
        'sslcert' => 'PGSSLCERT',
        'sslkey' => 'PGSSLKEY',
    ];

    public function __construct(
        public string $host,
        public int $port,
        public string $database,
        public string $username,
        /** Null when the connection genuinely has none — a trust or peer-authenticated setup. */
        public ?string $password = null,
        /**
         * The TLS settings the connection sets, by their key in {@see self::TLS_VARIABLES}.
         *
         * @var array<string, string>
         */
        public array $tls = [],
    ) {}

    /**
     * Assemble from a Laravel connection's configuration, or null when it is not complete enough.
     *
     * Null rather than a partially-filled object, and rather than defaults: see the class note.
     * The caller turns it into {@see PglsFailureReason::ConnectionIncomplete}, which names the
     * problem where a silent default would hide it.
     *
     * @param  array<string, mixed>  $config
     */
    public static function fromConfig(array $config): ?self
    {
        $host = $config['host'] ?? null;
        $database = $config['database'] ?? null;
        $username = $config['username'] ?? null;
        $port = $config['port'] ?? null;

        if (! is_string($host) || $host === '' || ! is_string($database) || $database === '' || ! is_string($username) || $username === '') {
            return null;
        }

        // The port is the one value with a defensible default, because PostgreSQL's is universal
        // and a Laravel connection routinely omits it. The other three are site-specific: there is
        // no correct guess for a host, and guessing one is how the tool ends up somewhere else.
        $port = is_numeric($port) ? (int) $port : 5432;

        $password = $config['password'] ?? null;
        $tls = [];

        foreach (array_keys(self::TLS_VARIABLES) as $key) {
            $value = $config[$key] ?? null;

            if (is_string($value) && $value !== '') {
                $tls[$key] = $value;
            }
        }

        return new self($host, $port, $database, $username, is_string($password) && $password !== '' ? $password : null, $tls);
    }

    /**
     * The environment this connection contributes to the child: the password, when there is one, and
     * the TLS settings it sets.
     *
     * An empty array when there is none, rather than an empty `PGPASSWORD`: the two are different
     * to libpq, and an empty value is a password attempt that fails rather than an absent one that
     * lets another authentication method run.
     *
     * @return array<string, string>
     */
    public function environment(): array
    {
        $environment = $this->password === null ? [] : [self::PASSWORD_VARIABLE => $this->password];

        foreach (self::TLS_VARIABLES as $key => $variable) {
            if (isset($this->tls[$key])) {
                $environment[$variable] = $this->tls[$key];
            }
        }

        return $environment;
    }
}
