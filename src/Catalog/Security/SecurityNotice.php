<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Security;

use Pushery\SQLens\Catalog\Degradation\CatalogNotice;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\CarriesNoSeverity;
use Pushery\SQLens\Contracts\ReportsWhatTheRunObserved;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;

/**
 * What a security reading could not cover, as an id a consumer can act on.
 *
 * Degradation is the NORMAL case here, not the exception. On RDS, Aurora, Cloud SQL and every other
 * managed instance, the account an application connects with cannot read parts of the security
 * catalog — and an audit that answered "no findings" from a reading it was refused would be the
 * silent green this package exists to prevent. So every refusal becomes a finding with a name.
 *
 * ## Why its own family beside `AUDIT.CATALOG.UNREAD`
 *
 * The two cover disjoint readings — that one the schema catalog, this one the security catalog — so
 * no event ever produces both, and each id says which reading fell short. They differ in the one
 * thing a consumer acts on: this family is `security` category, so a project can baseline or gate
 * what its managed provider withholds without also silencing gaps in the schema reading, which is a
 * different problem with a different fix.
 *
 * ## The area is in the ID, not only in the message
 *
 * `SEC.SKIPPED.PG.AUTHID` stays the same id whether the reason is a missing privilege today and an
 * unreadable catalog tomorrow. A baseline entry therefore survives a reason change, which is the
 * whole point of suppressing "my provider does not expose this" once rather than every quarter.
 *
 * @see CatalogNotice for the same shape covering the schema reading
 */
enum SecurityNotice: string implements RunNotice
{
    use CarriesNoSeverity;
    use ReportsWhatTheRunObserved;

    /** The family page for `SEC.SKIPPED.<DRIVER>.<AREA>` — part of the security reading was refused. */
    case SecuritySkipped = 'SEC.SKIPPED';

    /**
     * The security run performed no check at all — and that is not a clean result.
     *
     * Inside `SEC.SKIPPED.*` rather than beside it, and the id is where that is decided. The area
     * means "a check that could not run, reported as undetermined, never swallowed as a pass", and
     * a whole suite that examined nothing is the extreme case of exactly that — not a different
     * kind of thing. Standing outside as a bare `SEC.NOTHING_CHECKED` it had no area segment at
     * all, so every consumer that reads the area out of an id would have found one id that has
     * none. {@see coversFamily()} still says false: that is about whether the DOCS page describes
     * members, which is a separate question from which namespace the id lives in.
     *
     * The one state a suite must never report as a pass. Today it is the ordinary answer, because
     * `sqlens:security` is a shell with no sub-run wired into it yet; once the orchestration lands it
     * becomes the answer for a run whose filters admitted nothing, which is the same sentence for the
     * same reason. It does not expire with the scaffold — a suite that checked nothing has to say so
     * whatever the reason, or its silence is indistinguishable from a clean database.
     */
    case NothingChecked = 'SEC.SKIPPED.NOTHING_CHECKED';

    /** The prefix these report under — the audit run, not a rule. */
    public const string MESSAGE_PREFIX = 'sqlens.audit';

    /**
     * Where an unnamed area lands.
     *
     * Deliberately not derived from the reference by chopping prefixes: a derivation would invent a
     * plausible-looking id for a catalog nobody mapped, and an id that appears in no registry is one
     * a consumer cannot look up and a guard cannot notice is missing. An unmapped area says so.
     */
    public const string UNMAPPED = 'SEC.SKIPPED.OTHER';

    /**
     * The catalog each area is read from, as the readers name it, mapped to its id.
     *
     * Explicit rather than computed, and total by test: `tests/Unit/Catalog/Security/…` asserts that
     * every reference the two security readers actually pass is a key here, so a reader that starts
     * reading a new catalog cannot quietly report under the fallback.
     *
     * @var array<string, string>
     */
    private const array AREAS = [
        'pg_roles' => 'PG.ROLES',
        'pg_authid' => 'PG.AUTHID',
        'pg_auth_members' => 'PG.AUTH_MEMBERS',
        'pg_class.relacl' => 'PG.ACL',
        'pg_policy' => 'PG.POLICY',
        // Superuser-or-pg_read_all_settings only, and it REFUSES rather than omitting — so on a
        // managed instance this id is the normal answer, not the exception.
        'pg_hba_file_rules' => 'PG.HBA',
        // World-readable on PostgreSQL, so a refusal here is genuinely unusual — which is exactly why
        // it needs an id of its own rather than the fallback: on the one engine where this catalog can
        // be withheld, the withholding is the surprise worth naming.
        'pg_proc' => 'PG.PROC',
        'mysql.user' => 'MY.USER',
        'mysql.db' => 'MY.GRANTS',
        'mysql.role_edges' => 'MY.ROLE_EDGES',
        // MySQL's routine reading, and the one entry here whose absence was invisible: the guard that
        // keeps this map total read the readers with a LOWERCASE-only character class, so the
        // reference could not be seen at all. It fell through to `SEC.SKIPPED.OTHER` from the day the
        // routine reading landed, and the guard reported the map complete throughout.
        'mysql.routines' => 'MY.ROUTINES',
    ];

    /** The concrete id for one refused area — the family, then the catalog that was refused. */
    public static function idFor(string $reference): string
    {
        return isset(self::AREAS[$reference])
            ? self::SecuritySkipped->value.'.'.self::AREAS[$reference]
            : self::UNMAPPED;
    }

    /**
     * Every reference this family knows how to name.
     *
     * Exposed for the guard that keeps the map total. Sorted, so its failure message reads the same
     * on every machine.
     *
     * @return list<string>
     */
    public static function mappedReferences(): array
    {
        $references = array_keys(self::AREAS);
        sort($references);

        return $references;
    }

    public function id(): string
    {
        return $this->value;
    }

    public function messagePrefix(): string
    {
        return self::MESSAGE_PREFIX;
    }

    /**
     * Per case, not per enum. `SEC.SKIPPED` is a prefix with many concrete members and one page;
     * `SEC.SKIPPED.NOTHING_CHECKED` is a single id, and calling it a family would promise a page about
     * members it does not have.
     */
    public function coversFamily(): bool
    {
        return match ($this) {
            self::SecuritySkipped => true,
            self::NothingChecked => false,
        };
    }

    /**
     * `security`, which is the difference that earns this family its existence — a run notice about
     * the schema reading is a safety statement, and one about the security reading is not.
     */
    public function category(): Category
    {
        return Category::Security;
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function stability(): StabilityTier
    {
        return StabilityTier::Stable;
    }

    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->value);
    }

    /**
     * Where each notice can appear, and the two differ.
     *
     * `SEC.SKIPPED` comes out of the security READING, which the audit suite drives — so it surfaces
     * in an audit run. `SEC.SKIPPED.NOTHING_CHECKED` is the security suite's own statement about its own run
     * and belongs nowhere else; listing it under audit would send a reader to a command that never
     * emits it.
     *
     * @return list<Suite>
     */
    public function suites(): array
    {
        return match ($this) {
            self::SecuritySkipped => [Suite::Audit],
            self::NothingChecked => [Suite::Security],
        };
    }
}
