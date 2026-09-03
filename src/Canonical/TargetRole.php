<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * What a statement target IS TO the statement — the part its object type cannot say.
 *
 * ## The measurement that made this necessary
 *
 * `ALTER TABLE public.orders ADD CONSTRAINT … FOREIGN KEY (user_id) REFERENCES public.users (id)`
 * produces TWO table targets. They are not interchangeable: one is the table being altered, the
 * other is only mentioned. Nothing in `type` distinguishes them, and nothing else could — both
 * really are tables in the catalog's sense.
 *
 * Position does not carry it either, although it looks as if it should. `StatementClassifier` sorts
 * targets by `[type, qualifiedName]` before returning them, so which table comes first depends on
 * the NAME: measured on the real classifier, `public.orders` precedes `public.users` while
 * `public.accounts` precedes `public.orders`. "Take the first table target" is therefore correct for
 * the example everyone writes tests with and silently wrong for the next project's schema. Even
 * before the sort it would not hold — the PostgreSQL `CREATE INDEX` signature declares the index
 * before its table, while the whole `ALTER TABLE` family declares the table first.
 *
 * So the role is DECLARED on the signature element, at the one place that genuinely knows: the
 * grammar. It is a pure function of the canonical SQL, which is what keeps it deterministic.
 *
 * ## Why this is not a second object-type
 *
 * A `SchemaObjectType::ReferencedTable` was the obvious alternative and is the wrong axis. That enum
 * says WHAT a thing is in the catalog, and it is the primary sort key and the fingerprint's payload;
 * a referenced table is a table. Worse, it would silently change readers that are correct today —
 * `TouchedTables::of()` filters on `type === Table` and would simply stop seeing the referenced side
 * rather than start distinguishing it.
 *
 * ## What it deliberately does NOT do
 *
 * It does not enter `Fingerprint::targetPayload()`. The role is derived from the same canonical SQL
 * the fingerprint already covers, so including it would change every stored fingerprint and force a
 * canonical-form version bump to record no new information.
 */
enum TargetRole: string
{
    /**
     * The statement acts on this object.
     *
     * The default, and it stays the default for every signature that has only one target of a type —
     * which is all but three in the package. A statement with one table target has a `Subject` one,
     * and every reader that was correct before this enum existed stays correct.
     */
    case Subject = 'subject';

    /**
     * The statement only POINTS AT this object; it is not being changed.
     *
     * Today: the `REFERENCES` side of a foreign key, on both engines. A reader asking "what does
     * this statement alter" must exclude it, and a reader asking "what does this statement touch"
     * may legitimately include it — which is exactly the distinction that did not exist before and
     * the reason this is a field rather than a filter someone applies by hand.
     */
    case Referenced = 'referenced';
}
