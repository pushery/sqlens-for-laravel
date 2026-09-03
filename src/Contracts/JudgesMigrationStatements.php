<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\AbstractSafetyRule;
use Pushery\SQLens\Rules\MigrationVerdicts;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A catalog rule that can ALSO answer from a migration statement — the mirror image of
 * {@see JudgesSchemaObjects}, and the other half of "one rule, two subjects".
 *
 * ## Why an interface and not a branch on the base
 *
 * {@see AbstractCatalogRule} carried a migration half once and lost it: the first rule built on it
 * had nothing to say about a migration, so the hook was machinery every catalog rule implemented by
 * returning null — reachable only from a test written to reach it, which is the shape of a guard
 * that guards nothing. The base's docblock said the half comes back WITH its first user, and this
 * is that user's door: a catalog rule that really can decide something from migration text says so
 * by implementing this, and the twenty that cannot are untouched.
 *
 * ## When a rule should implement this
 *
 * When the QUESTION is the same and only the evidence differs, and the migration evidence can
 * settle a case rather than merely hint at one. "Is this foreign key covered by an index?" is one
 * question; the catalog answers it about every table that exists, and a migration answers it for
 * the narrow case where the migration CREATES the table and therefore carries its whole index
 * history. Splitting that into two rules would be the same rule twice, free to drift on the one
 * thing that must not: what counts as a violation.
 *
 * A migration branch that cannot settle a case must stay silent rather than answer `undetermined`
 * on every statement — a finding that is identical across its occurrences and unactionable at its
 * site is documentation wearing a finding's clothes.
 *
 * The finding is built by {@see MigrationVerdicts} either way, so a rule reaching a migration
 * through this interface and one reaching it through {@see AbstractSafetyRule} produce the same
 * shape.
 */
interface JudgesMigrationStatements
{
    /**
     * The verdict about this statement — a flag, an undetermined, or null for nothing to say.
     *
     * One verdict rather than a list, unlike the catalog side: a migration finding is located at a
     * statement, so a second verdict for the same statement would be deduplicated away by rule id
     * and location and vanish without a word.
     */
    public function judgeStatement(MigrationStatementView $statement): ?RuleVerdict;
}
