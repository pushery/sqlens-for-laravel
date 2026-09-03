<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Reporting\Agent\Redactor;
use Pushery\SQLens\Reporting\CredentialRedaction;

/**
 * A credential value taken out of SQL text, found by the SHAPE of the statement.
 *
 * ## Why this is its own class rather than a method on the reporter
 *
 * It began as a private constant inside {@see Redactor}, which was
 * the right place while the markdown report was the only surface that published statement text. It
 * is not any more: a rule that quotes the statement it is reporting on hands the same text to the
 * JSON envelope, to SARIF and to a CI annotation, and none of those has a redactor.
 *
 * Fixing that inside the reporter would have meant a masker per surface — several sets of patterns
 * agreeing for a long time and then disagreeing once, quietly, in whichever direction nobody looks.
 * So the patterns live here, in the domain, and both the reporter and {@see StatementExcerpt} read
 * them.
 *
 * ## By shape, never by value
 *
 * The keyword that introduces a secret is the same in every project; the secret itself is different
 * in every one. A list of known example passwords would catch exactly the passwords somebody had
 * already thought of — the class of guard this package refuses everywhere.
 */
final readonly class SecretLiteralMask
{
    /**
     * What a masked value is replaced by.
     *
     * The one definition in the package: {@see CredentialRedaction} takes
     * its own constant from this one. Deliberately visible — a reader must see that something was
     * there, and a silently shortened sentence would be the "no silent green" failure one layer
     * down.
     */
    public const string PLACEHOLDER = '<redacted>';

    /**
     * The statement shapes that carry a password literal, per engine family.
     *
     * The quoted-string forms cover PostgreSQL's `'…'` and MySQL's `'…'`/`"…"`; the bare form covers
     * `IDENTIFIED BY secret` without quotes, which MySQL has historically accepted.
     *
     * @var list<string>
     */
    private const array SECRET_PATTERNS = [
        // PASSWORD '…' / PASSWORD "…" — CREATE USER, ALTER ROLE, ALTER USER, CREATE ROLE. The
        // optional ENCRYPTED is PostgreSQL's second spelling of the same clause.
        '/(\bPASSWORD\s+)(\'[^\']*\'|"[^"]*")/i',
        // MySQL: IDENTIFIED BY '…' and IDENTIFIED WITH … BY '…'.
        '/(\bIDENTIFIED\s+(?:WITH\s+\S+\s+)?BY\s+)(\'[^\']*\'|"[^"]*")/i',
        // The unquoted MySQL form, ended by whitespace, a semicolon or a closing paren.
        //
        // `RANDOM PASSWORD` is excluded, and the exclusion is not cosmetic. It is MySQL 8's
        // generated-password form — the shape this package RECOMMENDS, in which the value never
        // appears in the statement at all. Without the lookahead the mask rewrote it to
        // `IDENTIFIED BY <redacted> PASSWORD`, so the one statement that had nothing to hide read
        // like the one that did. `PasswordLiteralRule` already refuses to fire on it for the same
        // reason; the two now agree.
        //
        // The lookahead requires the whole phrase, so a bare `IDENTIFIED BY RANDOM` — an account
        // whose password really is that word — is still masked.
        '/(\bIDENTIFIED\s+BY\s+)(?!RANDOM\s+PASSWORD\b)([^\s;\'")]+)/i',
        // MySQL's assignment form — `SET PASSWORD FOR … = '…'`. The `PASSWORD` pattern above does
        // not reach it: the keyword is followed by `FOR`, not by the literal.
        '/(\bSET\s+PASSWORD\b[^=]*=\s*)(\'[^\']*\'|"[^"]*")/i',
        // A DSN or URL carrying `user:password@` — the shape a connection string takes wherever it
        // is written down, including inside a migration that builds one.
        '/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:\/@]+:)([^\s@]+)(@)/i',
    ];

    /** The text with every credential literal replaced, and everything else untouched. */
    public static function in(string $text): string
    {
        $masked = $text;

        foreach (self::SECRET_PATTERNS as $pattern) {
            $replaced = preg_replace_callback(
                $pattern,
                static fn (array $match): string => $match[1].self::PLACEHOLDER.($match[3] ?? ''),
                $masked,
            );

            // A pattern that failed to run leaves the text as it was rather than emptying it.
            // `preg_replace_callback` answers null on a backtrack limit, and a null assigned here
            // would turn a message into nothing at all — which is the one outcome worse than an
            // unmasked one, because it looks like a check that found nothing.
            $masked = $replaced ?? $masked;
        }

        return $masked;
    }
}
