<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Pedantic;

use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Whether a schema object carries a comment, and whether anybody should be asked about it.
 *
 * ## The false-positive risk here is the highest in the catalog
 *
 * Every Laravel application ships tables it did not write: `migrations`, `jobs`, `failed_jobs`,
 * `cache`, `sessions`, `password_reset_tokens`. None of them will ever carry a comment, and none of
 * them should — nobody documents a framework table, and a finding on one is a finding the reader
 * cannot act on. Without the default exemption this rule reports double digits on a brand-new
 * application, which is the fastest way to have it switched off along with everything around it.
 *
 * So the framework set is exempt BY DEFAULT and the exemption is a prefix list a project can
 * replace. It is the rule's own, deliberately: extension-owned objects are already filtered out of
 * the object stream by the catalog reader, and re-implementing that here would be a second answer
 * to a question already answered. This one is different — it is a judgment about what a TEAM
 * documents, not about what the catalog owns.
 *
 * ## What "no comment" is, per engine, measured
 *
 * ```
 * PG 18.4    obj_description / col_description  →  NULL when absent
 * MY 8.4.10  TABLE_COMMENT / COLUMN_COMMENT     →  '' when absent
 * MY 8.4.10  TABLE_COMMENT on a VIEW            →  the literal word 'VIEW'
 * ```
 *
 * The readers normalize all three to `null`, so this class sees one shape. The third is the one
 * that would have been silent: a rule reading `VIEW` as documentation reports every view in every
 * MySQL schema as documented.
 */
final readonly class MissingComment
{
    /**
     * The tables a Laravel application does not write, and will never comment.
     *
     * Matched as whole names against the object's bare name, never as substrings: a project's own
     * `job_applications` table is not the framework's `jobs`, and a prefix match would exempt it.
     *
     * @var list<string>
     */
    public const array FRAMEWORK_TABLES = [
        'cache',
        'cache_locks',
        'failed_jobs',
        'job_batches',
        'jobs',
        'migrations',
        'password_reset_tokens',
        'password_resets',
        'personal_access_tokens',
        'sessions',
        'telescope_entries',
        'telescope_entries_tags',
        'telescope_monitoring',
    ];

    /** Whether this object carries a comment somebody wrote. */
    public static function documented(SchemaObject $object): bool
    {
        $comment = $object->getString('comment');

        return $comment !== null && trim($comment) !== '';
    }

    /**
     * Whether the catalog reading established anything about this object's comment at all.
     *
     * A reader that never asked and a reader that asked and got nothing must not look the same. The
     * two engines answer the question for every object they return, so `false` here means the
     * reading was partial — and the rule reports that as undetermined rather than as a missing
     * comment, which would accuse a schema of something nobody measured.
     */
    public static function readable(SchemaObject $object): bool
    {
        return $object->hasAttribute('comment') || $object->isFullyUnderstood();
    }

    /** The last segment of a qualified name — `public.orders` is `orders`. */
    public static function bareName(string $qualifiedName): string
    {
        $parts = explode('.', $qualifiedName);

        return trim(end($parts), '"`[] ');
    }
}
