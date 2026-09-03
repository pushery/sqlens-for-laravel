<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Guard\Violations\Violation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\ParametrizationSignal;

/**
 * A statement that carries a value where a binding belongs.
 *
 * ## What it can see, and what it cannot
 *
 * By the time a query reaches `QueryExecuted` the bindings are still separate from the SQL — so a
 * statement built with `?` placeholders arrives with placeholders, and one built by concatenating a
 * variable arrives with the value sitting in the SQL text. That difference is visible, and it is
 * the whole signal here.
 *
 * What it CANNOT see is whether the value came from user input. A hand-written `where status =
 * 'active'` is a literal and perfectly safe; the same shape with a request parameter in it is an
 * injection. Nothing at this layer separates them, and this guard does not pretend to: it reports a
 * SHAPE, at a level a reader can filter, and says so in its message.
 *
 * That honesty is why it is a guard and not a security rule. `sqlens:analyse` answers the injection
 * question properly, by reading the code that BUILT the statement — where the difference between a
 * constant and a request parameter is actually visible.
 *
 * ## Why the quoted-literal test and not a placeholder count
 *
 * "No bindings" is not the signal: a great many correct statements have none. What matters is a
 * quoted literal or a bare number in a comparison, which is what concatenation leaves behind.
 *
 * ## It shares the VOCABULARY with the static analyzer, and cannot share the analyzer
 *
 * {@see ParametrizationSignal} is the same three-valued enum `ParameterizationAnalyzer` answers
 * with, and this guardrail reports in it — so a consumer joining the static and runtime layers reads
 * one vocabulary rather than two that are free to drift.
 *
 * Reusing the ANALYZER was measured and is structurally impossible: it takes a PHP-Parser `Expr` and
 * a PHPStan `Scope`, because it reasons about the CODE THAT BUILT the statement. At runtime that
 * code is gone — a listener sees the finished string and an array of bindings, and nothing about
 * where either came from. That is not an implementation gap, it is the reason the two layers exist:
 * one can see whether a value came from a request, and this one cannot, which is exactly why it
 * reports a shape and says so.
 */
final readonly class UnboundRawSqlGuard implements QueryInspector
{
    public function __construct(private ViolationLogger $logger) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->unboundRawSql;
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        if (! $this->carriesLiteral($query->sql)) {
            return;
        }

        $this->logger->record($profile, Violation::found(
            type: 'unbound_raw_sql',
            // The one guardrail here whose category is SECURITY, and therefore the one that carries
            // a severity. It raises the log level above the profile's floor, so a record about a
            // possible injection surface does not arrive at the same level as a slow query — the two
            // axes this package keeps apart everywhere else would otherwise be flattened in the one
            // output somebody pages on.
            category: Category::Security,
            message: 'a statement carries a literal value where a binding would go',
            connection: $query->connectionName,
            sql: $query->sql,
            bindings: $query->bindings,
            // The SAME enum the static analyzer answers with. `interpolated` is a syntactic
            // observation — "the text carries a value where a placeholder would go" — and never a
            // security verdict, which is a distinction that type was created to hold.
            context: ['parametrization' => ParametrizationSignal::Interpolated->value],
            // MEDIUM and not high: what was observed is a SHAPE, and the shape is equally what a
            // hand-written constant produces. Rating it high would put a guess beside the facts the
            // catalog states.
            severity: Severity::Medium,
        ));
    }

    /**
     * Whether a comparison in this statement is against a LITERAL rather than a placeholder.
     *
     * Deliberately narrow. It looks for a comparison operator or `LIKE` followed by a quoted string,
     * which is the shape string concatenation produces. A bare number is NOT matched: `limit 10`,
     * `offset 0` and `where deleted_at is null` are ordinary, and a guard that reported them would
     * fire on nearly every query an application runs.
     */
    private function carriesLiteral(string $sql): bool
    {
        return preg_match('/(?:=|<>|!=|<|>|\blike\b|\bin\b\s*\()\s*\'[^\']*\'/i', $sql) === 1;
    }
}
