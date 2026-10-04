<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Illuminate\Contracts\Config\Repository;
use InvalidArgumentException;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;
use Pushery\SQLens\Security\SecretLiteralMask;
use Throwable;

/**
 * A database error's message, with the connection's own values taken out of it.
 *
 * ## The measurement that produced this
 *
 * A recorded MCP session against a connection whose every field was a marked string came back
 * carrying all of them:
 *
 *     the server would not say whether it accepts writes (SQLSTATE[08006] [7] could not translate
 *     host name "…" to address: … (Connection: …, Host: …, Port: 5432, Database: …, SQL: SET
 *     statement_timeout = '5000ms'))
 *
 * That trailing block is Laravel's own: `QueryException` appends the connection name, host, port,
 * database and SQL to whatever the driver said. So this is not a case of somebody having pasted a
 * DSN into a message — it is what a database error MESSAGE is, and every site that quotes one
 * inherits it.
 *
 * ## Why redaction rather than a per-site rewrite
 *
 * Eleven check classes quote an exception message today, and each has a good reason to: the reason a
 * check could not answer is exactly what a reader needs. Rewriting all eleven to classify instead
 * would lose that, and the twelfth would arrive without the treatment. And the driver's OWN text is
 * outside anybody's control — a future PostgreSQL release could name a host in a sentence nobody
 * anticipated.
 *
 * So the values themselves are removed, by value, from whatever the message turned out to be.
 * Replaced rather than deleted: a reason that says `host <redacted>` still tells a reader which
 * FIELD was involved, and a silently shortened sentence would be the "no silent green" failure one
 * layer down — the message must get smaller, never emptier.
 *
 * ## What it does not claim
 *
 * It removes what this application CONFIGURED. A value a server volunteers that nothing here knows
 * about — a replication slot name, a role the message mentions — is not covered, and pretending
 * otherwise would be the more dangerous mistake. This is one layer of several; the guard that reads
 * a whole session transcript is what says whether the layers together hold.
 */
final readonly class CredentialRedaction
{
    /**
     * What a removed value is replaced with. Deliberately visible: a reader must see that something
     * was there.
     *
     * Taken from {@see SecretLiteralMask} rather than spelled again: the two classes mask different
     * things — configured values here, statement shapes there — and a report in which they left
     * different markers would read as two different kinds of absence.
     */
    public const string PLACEHOLDER = SecretLiteralMask::PLACEHOLDER;

    /**
     * The fields whose value must go wherever it appears, even inside a longer token.
     *
     * A password embedded in a DSN, a log line or a quoted literal is still the password. The cost
     * of masking one character too many here is a slightly uglier message; the cost of masking one
     * too few is the secret.
     *
     * @var list<string>
     */
    private const array EXACT_FIELDS = ['password', 'url', 'dsn'];

    public function __construct(private Repository $config) {}

    /** A throwable's message, redacted. */
    public function fromThrowable(Throwable $error): string
    {
        return $this->in($error->getMessage());
    }

    /** Any text, with every configured connection value taken out of it. */
    public function in(string $text): string
    {
        $masked = str_replace($this->secrets(self::EXACT_FIELDS), self::PLACEHOLDER, $text);

        // The IDENTIFYING values — host, user, database, socket path — are masked only where they
        // stand as a token of their own.
        //
        // Measured, and it is not a hypothetical: a project whose database is called `laravel` — the
        // framework's own default — had every documentation URL in its report corrupted, because
        // `sqlens-for-laravel` contains that word. A substring replace over an identifier turns a
        // report into one nobody can follow a link out of, and the value it protected was a
        // database NAME, which is not the class of secret a password is.
        foreach ($this->secrets(self::IDENTIFYING_FIELDS) as $value) {
            $replaced = preg_replace(
                '/(?<![A-Za-z0-9_.-])'.preg_quote($value, '/').'(?![A-Za-z0-9_.-])/',
                self::PLACEHOLDER,
                $masked,
            );

            // A pattern that could not run leaves the text as it was. A null assigned here would
            // empty the message, which reads as a run that had nothing to say.
            $masked = $replaced ?? $masked;
        }

        return $masked;
    }

    /**
     * The identifying half — masked only as a whole token.
     *
     * @var list<string>
     */
    private const array IDENTIFYING_FIELDS = ['host', 'username', 'database', 'unix_socket'];

    /**
     * Every value this application's database configuration holds that must not travel.
     *
     * Read fresh rather than cached: a test — and a tenant-aware application — reconfigures
     * connections at runtime, and a cache would redact yesterday's values out of today's message.
     *
     * Sorted by LENGTH, longest first, and containment is the reason rather than any notion of which
     * value matters most. A database named `app` inside a host named `app.internal` would, removed
     * first, leave `<redacted>.internal` behind and make the host look partly intact.
     *
     * `port` is in neither field list on purpose: a port number is neither secret nor distinctive,
     * and removing `5432` from a message would blank out any number that happened to match.
     *
     * @param  list<string>  $fields  which of the configured fields to collect
     * @return list<string>
     */
    private function secrets(array $fields): array
    {
        $connections = $this->config->get('database.connections');
        $secrets = [];

        foreach (is_array($connections) ? $connections : [] as $connection) {
            if (! is_array($connection)) {
                continue;
            }

            foreach ($this->scopesOf($connection) as $scope) {
                foreach ($fields as $field) {
                    // A host can be a list. Laravel accepts `'host' => ['replica-1', 'replica-2']`
                    // and picks one per request, so an `is_string()` test on its own would skip every
                    // host of every multi-host connection — silently, because a skipped value looks
                    // exactly like a connection that configured none.
                    foreach (is_array($scope[$field] ?? null) ? $scope[$field] : [$scope[$field] ?? null] as $value) {
                        // A number counts as well: the framework's URL parser turns a password of
                        // digits into an integer, and the driver still quotes it as text.
                        $value = is_int($value) || is_float($value) ? (string) $value : $value;

                        // Short values are left alone: removing a host called `db` would blank out the
                        // letters `db` wherever they appeared, including inside the word a reader needed.
                        // Four characters is the floor at which a value is distinctive enough to be worth
                        // removing — and a secret shorter than that was never a secret.
                        if (is_string($value) && strlen($value) > 3) {
                            $secrets[] = $value;
                        }
                    }
                }
            }
        }

        $unique = array_values(array_unique($secrets));

        // Longest first, so a value contained inside another cannot leave a fragment of it behind.
        usort($unique, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return $unique;
    }

    /**
     * Every place a connection keeps the values it connects with.
     *
     * The read/write split nests its credentials, so the blocks are read as well as the top level.
     * Laravel lets each block override `host`, `username`, `password`, `database` and `port`, and a
     * replica's password is the one credential most likely to differ from the primary's. A block is
     * written in one of two shapes: a single set of keys, or a LIST of them the framework picks from
     * at random, where the values sit one level deeper. This package is pointed at production and
     * reports what it read, and a report is pasted into a ticket; reading one shape only would make
     * the redaction weakest exactly where the topology is most complicated.
     *
     * Each place is read a second time with its `url` taken apart. On a `url` connection the URL's
     * parts are the values the framework connects with, and a driver's message quotes them one by
     * one; masking the URL as a whole string leaves every one of them in the message. A URL the
     * framework cannot parse either is still masked whole, and taking it apart is skipped rather
     * than allowed to stop the message from being redacted at all.
     *
     * @param  array<array-key, mixed>  $connection
     * @return list<array<array-key, mixed>>
     */
    private function scopesOf(array $connection): array
    {
        $scopes = [$connection];

        foreach ([$connection['read'] ?? null, $connection['write'] ?? null] as $block) {
            foreach (is_array($block) && array_is_list($block) ? $block : [$block] as $entry) {
                if (is_array($entry)) {
                    $scopes[] = $entry;
                }
            }
        }

        foreach ($scopes as $scope) {
            if (! is_string($scope['url'] ?? null)) {
                continue;
            }

            try {
                $scopes[] = EffectiveConnectionConfig::withoutUrl($scope);
            } catch (InvalidArgumentException) {
                continue;
            }
        }

        return $scopes;
    }
}
