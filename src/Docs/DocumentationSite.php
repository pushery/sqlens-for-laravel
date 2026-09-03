<?php

declare(strict_types=1);

namespace Pushery\SQLens\Docs;

use Pushery\SQLens\Rules\RuleDocumentationUrl;

/**
 * Where this package's documentation lives — the host and the package's own route, once.
 *
 * Every address the package hands a user is built from here: the per-rule pages
 * ({@see RuleDocumentationUrl}), the per-driver pages, and the `$id` of the
 * bundled JSON schemas. They used to be written out one by one, and that is precisely how the
 * package came to ship two addresses for one set of pages — the prose linked the portal, where
 * the pages are, while every rule message and every driver linked a host that never carried them.
 *
 * Nothing failed, and nothing could: a link is a string, and a string that points nowhere looks
 * exactly like one that points somewhere. Only a reader following it finds out. Naming the site
 * once is what turns "move the docs" from a sweep with a missable file into a one-line change.
 *
 * The portal serves every package from `<host>/<repository>/`, so the route is the repository
 * name and the sections below it are ordinary directories in the documentation tree.
 */
final readonly class DocumentationSite
{
    /**
     * The package's documentation root, trailing slash included.
     *
     * Public API from 1.0 by consequence rather than by intent: it is the prefix of every link a
     * finding carries, so moving it moves published URLs.
     */
    public const string BASE = 'https://docs.pushery.com/sqlens-for-laravel/';

    /**
     * The address of a page, given its path below the package root.
     *
     * The trailing slash is not cosmetic: the portal serves a leaf page only WITH one. Measured, not
     * assumed — `…/rules/cap-l0-down-failed` answers 404 while `…/rules/cap-l0-down-failed/` answers
     * 200, and the same holds for the prose pages. The portal's own navigation links the slash-less
     * form and gets away with it because client-side routing never asks the server; a link this
     * package hands a user is followed directly, and dies.
     *
     * A path that already ends in a slash keeps exactly one, and a path naming a FILE — the bundled
     * JSON schemas carry an `$id` under this host — gets none: a slash after `.json` would name a
     * directory that does not exist.
     */
    public static function page(string $path): string
    {
        $path = ltrim($path, '/');

        if ($path === '' || str_ends_with($path, '/') || str_contains(basename($path), '.')) {
            return self::BASE.$path;
        }

        return self::BASE.$path.'/';
    }
}
