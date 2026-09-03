<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Rule;

/**
 * The common ground under every safety rule — the driver families (PostgreSQL, later
 * MySQL) and the driver-neutral migration-lifecycle rules alike. It is Core-pure: it
 * imports no driver, so a lifecycle rule that lives in Core can extend it without the
 * architecture test's Core→Drivers ban biting, and a driver's rule family extends it too.
 *
 * It exists so dozens of rules do not each invent their own conventions, and it is
 * deliberately narrow: a subclass says what it looks for and what it means, and gets
 * everything else — identity, documentation URL, category, suite, the finding's shape —
 * derived rather than repeated.
 *
 * **A rule sees only the CANONICAL statement.** {@see judge()} receives the canonical
 * form and nothing else; there is no accessor for the raw grammar output anywhere on
 * this class. That is not a convenience, it is the defense against grammar drift: a
 * rule that matched Laravel's formatting would break the day the framework changed a
 * space, and would meanwhile be matching the formatter rather than the SQL.
 *
 * **Identity is derived once, from the id.** The message prefix and the documentation
 * URL both come from `<AREA>.L<level>.<SLUG>`, so an id and its URL cannot drift apart and
 * nobody hand-maintains a link table. The slug is the id lowercased with dots AND
 * underscores turned into dashes — the SAME slug the fixture directories use and the
 * same one every already-shipped rule declares, so one id has one slug everywhere: from
 * an id a reader reaches both the page and the fixture without knowing which family the
 * rule belongs to.
 *
 * **Stability defaults from one named place.** Rules written before 1.0 are `stable`,
 * because the preview obligation exists to protect a published API and there is not yet
 * one to protect. Every rule added AFTER 1.0 starts as `preview` — and that switch is a
 * single constant here, not a decision repeated in dozens of files.
 */
abstract class AbstractSafetyRule implements Rule
{
    // Everything about being asked about a migration. Extracted so the security family can share
    // it — see the trait for why that could not be done by extending this class.
    use ReadsMigrationStatements;

    /** Every rule in this family is a safety rule; that is what the family means. */
    final public function category(): Category
    {
        return Category::Safety;
    }
}
