<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

/**
 * Which Laravel methods actually hand SQL text to the database — MEASURED against the framework,
 * never remembered.
 *
 * A guessed method name is a defect in both directions and only one of them is visible. A name that
 * does not exist is dead weight nobody notices; a name that exists and is missing means the rule is
 * silent on real raw SQL, in a project that believes it is covered. The second is why this list has
 * its own file and its own verification arm: `tests/Unit/Analyse/RawSqlSinksTest` reflects the
 * INSTALLED framework and fails if a listed method has disappeared or changed shape.
 *
 * Read out of `laravel/framework` v13.23.0 on 2026-08-14.
 *
 * ## Two kinds of sink, and the difference decides which rule may use which
 *
 * - A **statement sink** receives a COMPLETE statement and executes it. Reaching for one is a
 *   decision about how to talk to the database, which is what the policy rule asks about.
 * - A **fragment sink** contributes raw text to a statement the query builder assembles. Reaching
 *   for `whereRaw('status = ?', [$status])` is ordinary, idiomatic Laravel — asking a project to
 *   justify every one of them in writing is how a suite gets switched off in its first week. The
 *   injection rules read these, because the question there is not "was this a decision" but "did a
 *   runtime value reach the text".
 *
 * Keeping them apart in the vocabulary rather than in each rule is what stops the distinction from
 * being re-derived, slightly differently, by every consumer.
 */
final readonly class RawSqlSinks
{
    /**
     * Methods on `Illuminate\Database\Connection` — and therefore on the `DB` facade — that take a
     * complete SQL statement and run it.
     *
     * Every one verified present with a `$query` first parameter. Five of these were missing from
     * the first collector, so `DB::scalar('SELECT …')` and four of its siblings handed raw SQL to
     * the database and produced no finding at all — the silent direction, in a rule whose whole
     * purpose is to notice raw SQL.
     *
     * `pretend()` is deliberately absent: it takes a CALLBACK, not a statement, and the statements
     * inside it reach these same methods where they are seen normally.
     *
     * @var list<string>
     */
    public const array STATEMENT_SINKS = [
        'affectingStatement',
        'cursor',
        'delete',
        'insert',
        'scalar',
        'select',
        'selectFromWriteConnection',
        'selectOne',
        'selectResultSets',
        'statement',
        'unprepared',
        'update',
    ];

    /**
     * The statement sinks whose NAME alone identifies a connection — nothing else in a Laravel
     * project declares them.
     *
     * It exists because the same twelve names mean two different things depending on the receiver,
     * and only some of them are ambiguous. Measured against the installed framework rather than
     * remembered — `RawSqlSinksTest` derives this set from `Query\Builder`, `Eloquent\Builder`,
     * `Relation` and `Model` and fails if the two disagree:
     *
     *     cursor  delete  insert  select  update      also declared on a builder or the model
     *     the other seven                             a connection and nothing else
     *
     * `$connection->statement(…)` on an UNRESOLVED receiver is therefore still worth an
     * `undetermined`: nobody writes `->unprepared()` on anything but a connection, so the name is
     * evidence on its own. `$repository->update([...])` is not — reporting every unresolved
     * `->update()` would put a finding on ordinary code in every project, which is the fastest way
     * to get the suite switched off.
     *
     * Note `cursor`: the first reading of this collision named four methods and missed it, because
     * `Query\Builder::cursor()` is easy to forget. That is precisely why the set is derived by a
     * test instead of typed from memory.
     *
     * @var list<string>
     */
    public const array CONNECTION_ONLY_SINKS = [
        'affectingStatement',
        'scalar',
        'selectFromWriteConnection',
        'selectOne',
        'selectResultSets',
        'statement',
        'unprepared',
    ];

    /**
     * Methods that contribute raw text to a statement the query builder assembles.
     *
     * Nine of the ten take the raw text first and a bindings array second — which is what makes
     * them a family rather than a list: the same two questions can be asked of every one of them.
     *
     * ## `raw` is the tenth, and it differs in the way that matters
     *
     * `raw(mixed $value)` takes the text first like the rest and then STOPS — measured against
     * v13.23.0, it has no bindings parameter at all. So it is the one member of this family with no
     * safe twin: `whereRaw('status = ?', [$status])` is the parameterized form of `whereRaw`, and
     * `DB::raw()` simply has none. That makes it more exposed than its siblings, not less, which is
     * the opposite of how a reader skimming for "takes bindings" would rank it.
     *
     * It is a fragment rather than a statement sink because it EXECUTES NOTHING: it wraps text in an
     * `Expression` that the grammar renders later. Putting it among the statement sinks would hand
     * it to the policy rule, and every `DB::raw('count(*)')` in an application would then need a
     * written justification — the fastest way to get the whole suite switched off.
     *
     * Two things follow for anyone adding to this list, and both are held by tests rather than by
     * this paragraph: `raw` lives on `Connection` as well as on the builder (so the receiver check
     * in {@see RawSqlFragmentCollector} accepts both), and it is reachable statically through the
     * `DB` facade (so {@see RawSqlExpressionCollector} exists for that call shape).
     *
     * @var list<string>
     */
    public const array FRAGMENT_SINKS = [
        'fromRaw',
        'groupByRaw',
        'havingRaw',
        'orHavingRaw',
        'orWhereRaw',
        'orderByRaw',
        'raw',
        'rawValue',
        'selectRaw',
        'whereRaw',
    ];

    /**
     * The fragment sinks that have NO bindings parameter, so no placeholder form of the call exists.
     *
     * It is here because a rule's ADVICE is part of its correctness. The interpolation finding tells
     * a reader to pass the value as a binding and shows the shape — `whereRaw('… = ?', [$value])` —
     * and for nine of the ten members that is exactly right. For `raw` it is impossible: the method
     * takes one argument. A finding that prescribes a call the framework does not offer teaches the
     * reader that the tool has not understood their code, which costs more than the finding was
     * worth.
     *
     * Derived rather than remembered: `RawSqlSinksTest` reflects every sink, collects the ones
     * without a `bindings` parameter, and fails if that set and this constant disagree. So a future
     * Laravel that gives `raw()` bindings, or grows another argument-less member, moves this list —
     * nobody has to notice.
     *
     * ⚠️ `unprepared` was missing until 2026-08-21, and the guard could not have found it: the
     * derivation walked `FRAGMENT_SINKS` alone, against `Query\\Builder`. `unprepared` is a
     * STATEMENT sink on `Connection`, so it sat outside the ground set of the very check that
     * exists to keep this list honest — the same shape as `raw` itself before 2026-08-17.
     *
     * The consequence was user-facing, not cosmetic. {@see RawInterpolationRule::remedy()} reads
     * this list to decide whether "pass it as a binding" is advice somebody can act on, so
     * interpolation inside `DB::unprepared()` was answered with `unprepared('… = ?', [$value])` —
     * a call the framework does not offer, on the one sink that executes its string with no
     * prepared statement at all.
     *
     * @var list<string>
     */
    public const array SINKS_WITHOUT_BINDINGS = [
        'raw',
        'unprepared',
    ];

    /**
     * The three methods a bare PDO handle offers for running a statement.
     *
     * ⚠️ THESE ARE NOT IN `STATEMENT_SINKS`, AND THAT SEPARATION IS THE WHOLE POINT. Every name in
     * that list is evidence on its own or close to it — nobody writes `->unprepared()` on anything
     * but a connection. `prepare`, `query` and `exec` are the opposite: a repository, a cache, an
     * HTTP client and a template engine may all declare them. Putting them in the same list would
     * make the fence around an unresolved receiver ({@see CONNECTION_ONLY_SINKS}) decide a question
     * it cannot answer here, and the suite would report ordinary code in every project.
     *
     * So they live apart and are matched ONLY against a receiver that resolves to `PDO`. The
     * collector that reads them says the same thing in its own words, because the two have to
     * agree and the reason is not obvious from either side alone.
     *
     * @var list<string>
     */
    public const array PDO_STATEMENT_SINKS = [
        'exec',
        'prepare',
        'query',
    ];

    /**
     * Names that LOOK like sinks and are not — recorded so nobody adds them back by reading a method
     * list and matching on `Raw`.
     *
     * The integer families take a column and a list of VALUES, and cast each value to an integer
     * before it reaches the statement. That cast is the entire reason they exist, so treating them
     * as raw-SQL sinks would report the mitigation as the problem.
     *
     * The rest are debugging helpers. They RENDER a statement for a human to read and execute
     * nothing at all — plus four accessors on `Connection` that hand back a PDO handle or the query
     * log and take no SQL at all.
     *
     * Those four were invisible until 2026-08-17, and their absence is the reason this list now
     * covers two classes. The guard that keeps the third state from existing walked `Query\Builder`
     * and nothing else, so a `*raw*` name that lives only on `Connection` was never asked about.
     * `raw` itself sat in exactly that blind spot — and had been written into the guard by hand as
     * already-accounted-for, which is the same hole with a lid on it.
     *
     * @var array<string, string> method => why it is not a sink
     */
    public const array NOT_SINKS = [
        'whereIntegerInRaw' => 'takes a column and values, and casts every value to an integer before it reaches the statement — the cast is why the method exists',
        'whereIntegerNotInRaw' => 'the negated form of whereIntegerInRaw, with the same integer cast',
        'orWhereIntegerInRaw' => 'the or-form of whereIntegerInRaw, with the same integer cast',
        'orWhereIntegerNotInRaw' => 'the or-form of whereIntegerNotInRaw, with the same integer cast',
        'toRawSql' => 'renders the statement as text for a human to read; executes nothing',
        'dumpRawSql' => 'prints the rendered statement while debugging; executes nothing',
        'ddRawSql' => 'prints the rendered statement and halts; executes nothing',
        'getRawBindings' => 'returns the bindings already collected; takes no SQL at all',
        'getRawPdo' => 'hands back the write PDO handle; takes no SQL at all',
        'getRawReadPdo' => 'hands back the read PDO handle; takes no SQL at all',
        'getRawDirectPdo' => 'hands back the PDO handle without resolving a lazy connection; takes no SQL at all',
        'getRawQueryLog' => 'returns statements already run, for a human to read; runs nothing itself',
    ];
}
