<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Reporting\CredentialRedaction;

/**
 * The `Statement: …` excerpt a security rule appends to its finding.
 *
 * ## Why one class rather than the six private copies it replaces
 *
 * Six rules carried a byte-identical `excerpt()` — collapse the whitespace, truncate at 160. That
 * was fine while it was only formatting. It stopped being fine the moment the text could contain a
 * credential, because a defect in formatting is one edit and a defect in disclosure is six.
 *
 * Measured, on the statement that produced this class:
 *
 *     CREATE USER 'app'@'%' IDENTIFIED BY '<secret>'
 *
 * `PasswordLiteralRule` withholds its excerpt for exactly this reason and says so in its docblock.
 * `WildcardHostGranteeRule`, firing on the same statement for the wildcard host, printed it in full
 * — into the JSON report, the SARIF file and the CI annotation, none of which has a redactor. The
 * password rule's care was real and reached one rule out of seven.
 *
 * ## Masking happens BEFORE truncation, and the order is the whole point
 *
 * Truncating first makes disclosure depend on statement length: the same account, created with two
 * more options in front of it, keeps its password or loses it depending on where character 160
 * lands. Worse, a cut through the middle of a literal leaves a partial secret that no pattern will
 * ever match again. So the value goes first, and what gets truncated is already safe.
 *
 * ## What it does NOT do
 *
 * It does not mask the connection's configured values — that is
 * {@see CredentialRedaction}, which compares against what this
 * application configured and belongs where a run's configuration is resolved. A statement in a
 * migration file has no connection behind it.
 */
final readonly class StatementExcerpt
{
    /**
     * Where a quoted statement is cut.
     *
     * Long enough that an ordinary `GRANT` or `CREATE USER` arrives whole, short enough that a
     * generated migration with fifty columns does not push the advice off the bottom of a CI log.
     */
    public const int MAX_LENGTH = 160;

    /** The statement as a finding should quote it: one line, credential-free, bounded. */
    public static function of(string $canonical): string
    {
        $collapsed = trim((string) preg_replace('/\s+/', ' ', $canonical));

        $masked = SecretLiteralMask::in($collapsed);

        return mb_strlen($masked) > self::MAX_LENGTH
            ? mb_substr($masked, 0, self::MAX_LENGTH - 3).'…'
            : $masked;
    }
}
