<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Docs\DocumentationSite;

/**
 * Where a rule's documentation page lives, derived from its id and never hand-written.
 *
 * A finding carries a link, and from 1.0 that link is public API: it may not move, and it may not
 * 404. Both properties are easier to promise than to keep, so the address is computed in exactly
 * one place. Two rule families reach it — the safety rules through {@see AbstractSafetyRule}, and
 * the capture rules and pre-scan detectors, which are not safety rules and used to carry the URL
 * as a literal. Fifteen literals is fifteen chances to typo a slug that reads plausibly and
 * matches no page.
 *
 * ## The base
 *
 * Documentation is published on the shared portal under the package's own route, so a page for
 * `PG.L2.INDEX_NOT_CONCURRENT` lives at
 * `https://docs.pushery.com/sqlens-for-laravel/rules/pg-l2-index-not-concurrent/`.
 *
 * It used to say `sqlens.io/rules/…`, which was never where the docs went: the portal serves every
 * package from `docs.pushery.com/<repository>/`, and the prose docs (README, the Boost skill, the
 * config comments) already linked there. So the package shipped two addresses for one set of
 * pages, and the one in every rule message was the broken half. Naming the host once is what makes
 * that a single-line correction instead of a sweep — which is the argument for computing it, made
 * concrete.
 *
 * ## The shape: flat, one segment
 *
 * `PG.L2.INDEX_NOT_CONCURRENT` becomes `pg-l2-index-not-concurrent`, not `pg/l2/index-not-concurrent`.
 * The slug is not only a URL: it names the fixture pair's directory and the documentation file, and
 * CONTRIBUTING states the rule as one id having one slug everywhere. A nested URL would break that
 * correspondence for the sake of tidier paths.
 */
final readonly class RuleDocumentationUrl
{
    /**
     * The one place the documentation host and section live.
     *
     * Public API from 1.0: changing it moves every rule link at once, which is precisely why it is
     * a single string and not a literal repeated per rule.
     */
    public const string BASE = DocumentationSite::BASE.'rules/';

    /**
     * The page address for a rule id — with the trailing slash the portal requires.
     *
     * Measured against the live site, not assumed: `…/rules/cap-l0-down-failed` answers 404 and
     * `…/rules/cap-l0-down-failed/` answers 200. Every documentation URL this package has ever put
     * in a finding was therefore dead on arrival, which is the most visible surface it has — the
     * link is what a user clicks when a rule tells them something they do not understand.
     *
     * The portal's own navigation links the slash-less form, and in a browser that works, because
     * client-side routing never asks the server. The 404 appears only on a DIRECT request — which is
     * exactly what a finding's URL gets: pasted out of a CI log into an address bar.
     */
    public static function for(string $ruleId): string
    {
        return self::BASE.self::slug($ruleId).'/';
    }

    /**
     * The slug of a rule id: lowercased, with BOTH separators — the dots between segments and the
     * underscores inside one — folded to dashes.
     *
     * The underscore is the part that is easy to get wrong, and it was: a slug that keeps it
     * produces `pg-l2-index_not_concurrent`, which reads plausibly and matches nothing. Every page
     * shipped so far is named the folded way, so a second, underscore-keeping derivation would
     * have split one convention into two, and the only visible symptom would have been a user
     * following a link that 404s.
     */
    public static function slug(string $ruleId): string
    {
        return strtolower(str_replace(['.', '_'], '-', $ruleId));
    }
}
