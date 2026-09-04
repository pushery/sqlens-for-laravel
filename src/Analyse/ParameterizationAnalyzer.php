<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use Pushery\SQLens\Subjects\FragmentOrigin;
use Pushery\SQLens\Subjects\ParametrizationSignal;

/**
 * Was the SQL at this call site fully written by its author, or did a runtime value reach its shape?
 *
 * This is the noise control the injection rules stand on. Without it every `whereRaw('status = ?',
 * [$status])` in a codebase is a finding, the suite gets switched off inside a week, and the real
 * findings go with it. So the classifier's job is as much about staying SILENT on ordinary Laravel
 * code as it is about noticing the dangerous shapes.
 *
 * ## One component, one owner
 *
 * Both the security injection rules and the driver-neutral policy rule read this class. There is
 * deliberately no second classifier anywhere in the package: two of them would be free to disagree,
 * both green, and a report would then depend on which one answered.
 *
 * ## Three values, and why they are not `safe` / `unsafe`
 *
 * The verdict reuses {@see ParametrizationSignal}, which the `RawSql` subject has carried since it
 * was defined. The naming is load-bearing: `parametrized` is an observation a parser can prove —
 * *the text is fully known at analysis time* — while `safe` is a security claim it cannot. This
 * package does not do taint analysis, so it does not use taint analysis' vocabulary.
 *
 * ## The boundary, stated rather than discovered
 *
 * The classifier sees EXACTLY ONE call site. It does not follow assignments across function
 * boundaries and does not track where a value came from. That is why an argument it cannot resolve
 * becomes {@see ParametrizationSignal::Undetermined} with a named reason and NEVER
 * {@see ParametrizationSignal::Parametrized} — the failure direction is the whole design. A value
 * assembled unsafely one method away is invisible here, and the honest answer to an invisible thing
 * is "I cannot tell", not "it is fine".
 *
 * It reads types, never values, and touches no database — it runs inside a static analyzer, where
 * there is nothing to connect to.
 */
final class ParameterizationAnalyzer
{
    /**
     * String builders whose output is assembly rather than a literal.
     *
     * They are recognized for the ORIGIN only. Whether such a call is parameterized is decided by
     * the resolved type just like everything else: `sprintf('ANALYZE %s', self::TABLE)` narrows to a
     * constant string and is parameterized despite sitting in this list, while the same call with a
     * variable does not. The list answers "how was this assembled", not "is it safe".
     */
    private const array STRING_BUILDERS = ['sprintf', 'vsprintf', 'implode', 'join', 'str_replace', 'strtr'];

    /**
     * Classify one raw-SQL argument.
     *
     * @param  Expr|null  $bindings  the call's bindings argument, when it has one. Used ONLY for the
     *                               coherence check below — never to decide whether the call is
     *                               parameterized, because that is a property of the SQL text.
     */
    public function classify(Expr $sql, ?Expr $bindings, Scope $scope): ParameterizationVerdict
    {
        $origin = $this->origin($sql);
        $texts = $this->constantTexts($sql, $scope);

        if ($texts === []) {
            // Nothing resolved to a literal. Either the assembly is visible in the syntax — an
            // interpolation, a concatenation, a string builder — or the argument is opaque, and
            // those are different answers rather than degrees of the same one.
            // …unless the assembly provably cannot carry a runtime VALUE, which is the one case
            // where "assembled" and "a value reached the statement" come apart. See
            // {@see carriesNoRuntimeValue()} for why that distinction is worth the code.
            if ($origin !== FragmentOrigin::UnknownVariable && $this->carriesNoRuntimeValue($sql, $scope)) {
                return ParameterizationVerdict::parametrized($origin);
            }

            // …and the second case where "assembled" and "a value reached the statement" come apart:
            // the value went through `Connection::escape()`, so what landed in the text is a VALUE
            // LITERAL. That is what a binding guarantees, at a position that accepts no binding —
            // PostgreSQL takes no placeholder for an identifier, a schema name or a DDL fragment,
            // measured with a positive control.
            //
            // Only `escape()`, deliberately. `Grammar::wrap()` is the other half of the same idiom
            // and is NOT admitted here: it stops the breakout and not the object choice — measured,
            // `wrap('other_schema.secrets')` yields `"other_schema"."secrets"`. It earns a truthful
            // remedy in {@see RawInterpolationRule}, never silence. See {@see EngineNeutralization}.
            if ($origin !== FragmentOrigin::UnknownVariable && EngineNeutralization::valueEscaped($sql, $scope)) {
                return ParameterizationVerdict::parametrized($origin);
            }

            return $origin === FragmentOrigin::UnknownVariable
                ? ParameterizationVerdict::undetermined($origin, UndeterminedReason::ArgumentTypeUnresolved)
                // Still interpolated — `wrap()` stops the breakout, not the object choice. The flag
                // travels so the finding can name a remedy that exists.
                : ParameterizationVerdict::interpolated($origin, EngineNeutralization::identifierQuoted($sql, $scope));
        }

        return $this->coherent($texts, $bindings, $scope)
            ? ParameterizationVerdict::parametrized($origin)
            : ParameterizationVerdict::undetermined($origin, UndeterminedReason::BindingCountMismatch);
    }

    /**
     * Do the constant SQL's placeholders and the constant bindings array agree on how many there are?
     *
     * A mismatch is NOT an injection — the text is constant, so nothing can be smuggled into it. It
     * is a bug that surfaces at runtime, and the classifier refuses to call a call site parameterized
     * while its own two halves contradict each other.
     *
     * Three ways this answers "yes, as far as I can tell", all deliberate:
     *
     * - **No bindings argument at all.** A placeholder with nothing to bind fails at runtime; it is
     *   still not an injection, and inventing doubt about it would report on a shape the author can
     *   already see fail.
     * - **A bindings array whose size is unknown.** `whereRaw('id IN (?)', $ids)` is the most ordinary
     *   safe shape in any Laravel codebase. Degrading it is exactly the noise this class prevents.
     * - **Several possible texts with different placeholder counts.** A constant-map lookup narrows
     *   to a union; when its members disagree there is no single count to check against, and the
     *   text is still entirely the author's.
     *
     * @param  list<string>  $texts
     */
    private function coherent(array $texts, ?Expr $bindings, Scope $scope): bool
    {
        if (! $bindings instanceof Expr) {
            return true;
        }

        $bound = $this->constantArraySize($bindings, $scope);

        if ($bound === null) {
            return true;
        }

        $counts = array_unique(array_map($this->countPlaceholders(...), $texts));

        return count($counts) !== 1 || reset($counts) === $bound;
    }

    /**
     * How many bind slots the statement declares.
     *
     * Positional `?` and named `:name`, counted syntactically. A `?` inside a quoted literal in the
     * SQL would be over-counted — an acknowledged limit, and one whose failure direction is the safe
     * one: an over-count produces a mismatch, a mismatch produces `undetermined`, and `undetermined`
     * is never read as a pass.
     *
     * `::` is excluded because PostgreSQL spells a cast that way, and reading `::text` as a named
     * parameter would turn every cast in a query into a phantom placeholder.
     */
    private function countPlaceholders(string $sql): int
    {
        $withoutCasts = str_replace('::', '', $sql);

        return substr_count($withoutCasts, '?')
            + (int) preg_match_all('/:[a-zA-Z_]\w*/', $withoutCasts);
    }

    /**
     * Every literal string this expression can be, or an empty list when it can be something else.
     *
     * The question is asked of the resolved TYPE rather than of the syntax, which is what makes a
     * class constant, a global constant and a constant-map lookup all answer correctly without this
     * class knowing anything about constants. A union — the allowlist pattern — comes back with one
     * entry per member, and a type that is merely `string` comes back empty.
     *
     * @return list<string>
     */
    private function constantTexts(Expr $sql, Scope $scope): array
    {
        $strings = $scope->getType($sql)->getConstantStrings();

        return array_map(static fn (object $string): string => (string) $string->getValue(), $strings);
    }

    /**
     * The element count of a bindings array whose shape is known, or null when it is not.
     *
     * Null is not doubt here — see {@see self::coherent()}, where it means "there is nothing to
     * check against", which is a different statement from "the check failed".
     */
    private function constantArraySize(Expr $bindings, Scope $scope): ?int
    {
        $arrays = $scope->getType($bindings)->getConstantArrays();

        return count($arrays) === 1 ? count($arrays[0]->getKeyTypes()) : null;
    }

    /**
     * How the text was assembled, read off the syntax.
     *
     * Syntax rather than type, because this is the one question the type cannot answer: `'ANALYZE '
     * .self::TABLE` and `'ANALYZE orders'` resolve to the same constant string and are different
     * things for a reader to go and look at. The origin is what survives into a finding's message —
     * S1 names the shape it saw instead of quoting the query, so a report never carries SQL text.
     */
    private function origin(Expr $sql): FragmentOrigin
    {
        return match (true) {
            $sql instanceof String_, $sql instanceof ClassConstFetch, $sql instanceof ConstFetch => FragmentOrigin::Literal,
            $sql instanceof InterpolatedString => FragmentOrigin::Interpolation,
            $sql instanceof Concat => FragmentOrigin::Concatenation,
            $sql instanceof FuncCall && $this->isStringBuilder($sql) => FragmentOrigin::Concatenation,
            default => FragmentOrigin::UnknownVariable,
        };
    }

    /** Is this a call to one of the functions that assemble a string out of parts? */
    private function isStringBuilder(FuncCall $call): bool
    {
        return $call->name instanceof Name
            && in_array(strtolower($call->name->toString()), self::STRING_BUILDERS, true);
    }

    /**
     * Can a runtime value reach the text this expression produces?
     *
     * ## The false positive this exists to stop, and why it is the expensive kind
     *
     * A variable-length `IN (…)` has exactly one safe spelling in PHP, and every Laravel codebase
     * writes it:
     *
     *     $placeholders = implode(', ', array_fill(0, count($ids), '?'));
     *     $reader->select(str_replace('ID_LIST', $placeholders, $sql), $ids);
     *
     * Nothing but `?` and `,` is assembled; the values travel as bindings. Reporting it says the
     * value reached the STATEMENT, which is factually wrong rather than merely strict — and the
     * consequence is worse than noise: a project that believes the report rewrites the canonical
     * SAFE form into something else. This package already refuses to report the
     * `whereIntegerInRaw` family for exactly that reason.
     *
     * ## The proof is a TYPE, not a shape, and that is what makes it sound
     *
     * `literal-string` is PHPStan's own statement that every possible value of a string was written
     * as a literal in the source. That IS the property this rule needs, stated by the analyzer that
     * already computed it. Measured:
     *
     *     implode(', ', array_fill(0, count($ids), '?'))   ->  literal-string
     *     str_repeat('?,', count($ids))                    ->  literal-string
     *     $ids === [] ? "''" : $placeholders               ->  literal-string
     *     $status  (a string parameter)                    ->  string
     *
     * A shape check could not tell those apart: `str_replace('LIST', $placeholders, $sql)` and
     * `str_replace('COL', $column, $sql)` are the same three nodes. The TYPE separates them, and it
     * keeps separating them for spellings nobody has written yet.
     *
     * ## Why the arguments are inspected rather than the result
     *
     * Measured too: `literal-string` does NOT survive `str_replace()` — PHPStan widens the result to
     * `string`. So the question is asked one level down, of each part the builder was handed, which
     * is also where the answer is meaningful: a builder is safe exactly when everything it was given
     * is.
     *
     * INTEGER arguments are skipped on purpose. `count($ids)` decides how MANY placeholders there
     * are, never what they say, and a length cannot smuggle a value into SQL.
     *
     * Anything else answers false and the previous verdict stands. That direction is the design:
     * this may only ever turn a finding OFF where the type proves there is nothing to find, never
     * turn an unresolved argument into a pass.
     */
    private function carriesNoRuntimeValue(Expr $expr, Scope $scope): bool
    {
        if ($scope->getType($expr)->isLiteralString()->yes()) {
            return true;
        }

        if ($expr instanceof Concat) {
            return $this->carriesNoRuntimeValue($expr->left, $scope) && $this->carriesNoRuntimeValue($expr->right, $scope);
        }

        return $expr instanceof FuncCall && $this->buildsFromValueFreeParts($expr, $scope);
    }

    /**
     * A call that assembles text, every string part of which is itself value-free.
     *
     * The function has to be one this class already recognizes as an assembler, plus those that
     * BUILD a repeated fragment rather than joining one (`array_fill`, `str_repeat`, `str_pad`) and
     * those that TRIM one (`rtrim`, `ltrim`, `trim`, `substr`). The first group turns a count into a
     * placeholder run; the second removes the trailing separator it leaves behind, which is how the
     * shape is actually written.
     *
     * The list is a whitelist rather than "any function", because a function this class does not
     * know could do anything at all with what it was handed — and answering true for it would be
     * the guess this method exists to avoid.
     */
    private function buildsFromValueFreeParts(FuncCall $call, Scope $scope): bool
    {
        if (! $call->name instanceof Name) {
            return false;
        }

        $function = strtolower($call->name->toString());

        if (! in_array($function, [...self::STRING_BUILDERS, 'array_fill', 'str_repeat', 'str_pad', 'rtrim', 'ltrim', 'trim', 'substr'], true)) {
            return false;
        }

        return array_all(
            $call->getArgs(),
            fn (Arg $arg): bool => $scope->getType($arg->value)->isInteger()->yes()
                || $this->carriesNoRuntimeValue($arg->value, $scope),
        );
    }
}
