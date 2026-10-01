<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Grammars\Grammar as SchemaGrammar;
use PDO;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\SchemaIntrospection;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Guard\Violations\Violation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\ParametrizationSignal;
use Throwable;

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
 * quoted literal in a comparison, which is what concatenating a string leaves behind. A bare number
 * is NOT matched, and that is a boundary rather than an oversight: the framework writes numbers into
 * statements itself, the integer keys of every eager load and the count of a `has()`, so a guard
 * that matched them would report nearly every request. A number concatenated into a statement is
 * therefore not reported here; `sqlens:analyse` reads the code that built it.
 *
 * ## What the framework writes itself is not reported
 *
 * Two shapes Laravel produces carry a quoted literal after an operator without any input in it:
 *
 * - a JSON path, `"meta"->>'email'`, where the `>` of `->>` is not a comparison;
 * - the schema builder's questions, `Schema::hasTable()` and the rest, which write the names they
 *   ask about as literals. They are recognized by the shape the connection's own schema grammar
 *   compiles ({@see SchemaIntrospection}), in the engine grammar the connection has registered.
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
    public function __construct(
        private ViolationLogger $logger,
        private ?CanonicalExtensionRegistry $grammars = null,
    ) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->unboundRawSql;
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        if (! $this->carriesLiteral($query->sql) || $this->isSchemaIntrospection($query)) {
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
     *
     * A `>` that ends a JSON operator (`->`, `->>`, `#>`, `#>>`) is not a comparison: the literal
     * after it is the path the query builder wrote, and the value it is compared with is bound.
     */
    private function carriesLiteral(string $sql): bool
    {
        return preg_match('/(?:=|<>|!=|<|(?<![-#>])>|\blike\b|\bin\b\s*\()\s*\'[^\']*\'/i', $sql) === 1;
    }

    /**
     * Whether the statement is the schema builder asking about the schema.
     *
     * No means "report it": without the connection's schema grammar or an engine grammar there is
     * nothing to compare the statement with, and a registry whose extension throws must cost this
     * check its answer, never the application its query.
     *
     * The connection's own handle has to be open already. Some grammars read the server version
     * while they compile a question, and on a connection whose handle is still waiting that read
     * connects; a guard on the query path does not open a connection, least of all a second one to
     * the primary of a read/write pair whose reads went to a replica.
     */
    private function isSchemaIntrospection(QueryExecuted $query): bool
    {
        $schemaGrammar = $this->schemaGrammarOf($query->connection->getSchemaGrammar());

        if (! $schemaGrammar instanceof SchemaGrammar
            || ! $query->connection->getRawPdo() instanceof PDO
            || ! $this->grammars instanceof CanonicalExtensionRegistry
        ) {
            return false;
        }

        try {
            $grammar = $this->grammars->forConnection($query->connectionName);
        } catch (Throwable) {
            return false;
        }

        return $grammar instanceof DriverCanonicalization
            && SchemaIntrospection::recognizes($query->sql, $schemaGrammar, StringLiteralMask::forDriver($grammar));
    }

    /**
     * The connection's schema grammar, or null while nothing has used the schema builder on it.
     *
     * Taken as `mixed` on purpose. The framework's docblock declares the getter non-null, while the
     * property behind it starts as null and stays null until something asks for the schema builder;
     * a statement on such a connection was not compiled by the builder.
     */
    private function schemaGrammarOf(mixed $grammar): ?SchemaGrammar
    {
        return $grammar instanceof SchemaGrammar ? $grammar : null;
    }
}
