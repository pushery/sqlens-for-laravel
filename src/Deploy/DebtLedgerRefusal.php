<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Why a ledger file could not be acted on, in the two words a caller needs and the sentence a
 * person needs.
 *
 * ## Why it travels with the ledger instead of being thrown
 *
 * A broken debt account must not make the rest of a run worthless. `sqlens:lint` still has
 * migrations to read and findings to report; only the checks that consult the ledger are affected,
 * and they are the ones that turn this into a named `undetermined`. An exception here would take
 * the whole run down over a file that is not even an input to most of it.
 *
 * ## Why there are two codes and not one, and not four
 *
 * The reason a caller reports is the one that tells somebody what to DO, and there are exactly two
 * things to do. A version this build cannot act on is fixed by moving a version — upgrade the tool,
 * or migrate the file. A file that is not a ledger at all is fixed by repairing or deleting it.
 * Splitting further (missing field vs. non-integer field) would give two codes to one action; a
 * single code would give one action to two problems. The `detail` says which of the specific cases
 * it was, because that is what a person reads.
 */
final readonly class DebtLedgerRefusal
{
    private function __construct(
        public UndeterminedReason $reason,
        public string $detail,
    ) {}

    /** The file says a version this build cannot act on — or does not say one at all. */
    public static function unsupportedSchema(string $path, string $found): self
    {
        return new self(
            UndeterminedReason::DebtLedgerSchemaUnsupported,
            sprintf(
                'the debt ledger at %s declares %s, and this build acts on schema %d only. It was '
                .'NOT read as an empty ledger: a file whose format this build cannot evaluate says '
                .'nothing about what the project owes, and reporting no debts here would be the one '
                .'answer that is both wrong and reassuring. Upgrade SQLens to a build that knows '
                .'this format, or migrate the file to schema %d.',
                $path,
                $found,
                DebtLedgerSchema::CURRENT,
                DebtLedgerSchema::CURRENT,
            ),
        );
    }

    /** The file is not a ledger — malformed JSON, or a shape with no entries in it. */
    public static function unreadable(string $path, string $because): self
    {
        return new self(
            UndeterminedReason::DebtLedgerUnreadable,
            sprintf(
                'the debt ledger at %s could not be read: %s. It was NOT read as an empty ledger — '
                .'a file nobody can parse is not a project without debts, and the difference is the '
                .'whole reason this account is kept. Repair the file from version control, or delete '
                .'it to start a new account deliberately.',
                $path,
                $because,
            ),
        );
    }
}
