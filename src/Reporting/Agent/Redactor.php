<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Pushery\SQLens\Reporting\CredentialRedaction;
use Pushery\SQLens\Security\SecretLiteralMask;

/**
 * Nothing this package writes for an agent may carry a credential VALUE.
 *
 * The report leaves the tool towards somebody else's agent and is routinely pasted into a chat, a
 * ticket or a commit. A rule catalog that reports a password literal in a migration as critical and
 * then reprints it in a markdown document has not protected anybody — it has widened the exposure
 * and attached a heading to it.
 *
 * ## Two different secrets, two different sources
 *
 * They are not the same problem and neither one covers the other:
 *
 * - **The active connection's values** — host, user, password, database, DSN. These are KNOWN
 *   strings, so they are masked by matching them, and {@see CredentialRedaction} already owns that
 *   comparison. It is used rather than reimplemented: a second masker would agree for a long time
 *   and then disagree once, quietly, in whichever direction nobody looks.
 * - **A password literal inside SQL a migration wrote** — `CREATE USER … PASSWORD '…'` and its
 *   relatives. This value is NOT known in advance; it is somebody's typo committed six months ago.
 *   So it is found by the SHAPE of the statement, never by a list of example passwords, which would
 *   only ever catch the passwords somebody already thought of.
 *
 * ## The finding survives; only the value goes
 *
 * A masked report still names the file, the line, the rule id and the object. That is everything
 * an agent needs to fix it — the value was never the actionable part, it was the damage.
 *
 * ## One seam
 *
 * Applied once, over the whole rendered document, rather than per section. A redactor invoked per
 * section is a redactor a new section can be written without, and the arm that would catch it is
 * the one nobody writes.
 */
final readonly class Redactor
{
    /** What a masked value is replaced by — the same marker the rest of the package uses. */
    public const string PLACEHOLDER = CredentialRedaction::PLACEHOLDER;

    public function __construct(private CredentialRedaction $connection) {}

    /**
     * The text with every credential value replaced, and everything else untouched.
     *
     * The connection pass runs FIRST. Its values are known exactly, so masking them first means a
     * password that appears both in the configuration and in a statement is gone before the shape
     * pass looks — and the shape pass then finds only the ones nobody configured, which is the set
     * it exists for.
     *
     * The shape pass used to be a pattern list right here. It moved to {@see SecretLiteralMask} when
     * a second surface needed it: a rule that quotes the statement it is reporting hands that text
     * to the JSON envelope and to SARIF, neither of which passes through this class. Two lists would
     * have agreed for a long time and then disagreed once, quietly.
     */
    public function in(string $text): string
    {
        return SecretLiteralMask::in($this->connection->in($text));
    }
}
