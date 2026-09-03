<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Pushery\SQLens\Deploy\DebtMode;

/**
 * The `--debt` flag, read the same way by every command that has one.
 *
 * ## Why it is shared rather than written twice
 *
 * Two commands can record now — `sqlens:lint` from the migrations it reads, `sqlens:audit` from the
 * catalog it reads — and the second one arrived because a debt only the catalog knows about could
 * never be dated. What must not arrive with it is a second opinion about what the flag MEANS: a
 * typo refused in one command and quietly treated as `check` in the other is exactly the kind of
 * difference nobody notices until an operator believes they recorded something and did not.
 *
 * The flag's DESCRIPTION stays per-command, deliberately. The two record different populations —
 * one what the migrations leave behind, one what the database already carried — and a shared
 * sentence would have to be vague about the thing a reader most needs to know.
 */
trait ResolvesDebtMode
{
    /**
     * The debt mode this run was asked for, or false when the flag names one that does not exist.
     *
     * False rather than a fallback to {@see DebtMode::Check}: an unknown value is almost always a
     * typo or a rename, and quietly doing the safe thing means the operator believes they asked for
     * a recording run and got a checking one. The message names every accepted spelling, so the
     * fix does not need the documentation.
     */
    private function validatedDebtMode(): DebtMode|false
    {
        $raw = $this->option('debt');

        if (! is_string($raw) || $raw === '') {
            return DebtMode::Check;
        }

        $mode = DebtMode::tryParse($raw);

        if (! $mode instanceof DebtMode) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.invalid_debt_mode', [
                'mode' => $raw,
                'available' => DebtMode::accepted(),
            ]));

            return false;
        }

        return $mode;
    }
}
