<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Config\RuleIdValidator;

/**
 * The machine form of the rule-id naming scheme documented in CONTRIBUTING.md.
 * Rule ids are public API from 1.0, so the scheme is fixed once, here, before the
 * first rule exists — the metadata property test (which runs over the whole
 * registry) consumes this so no rule can enter the catalog with a malformed id.
 *
 * The shape is `<AREA>.L<n>.<NAME>` for a leveled rule. AREA is one of PG, MY,
 * GEN, CAP; the level is L0..L9; NAME is UPPER_SNAKE and starts with a letter —
 * a stable, speaking name, never a meaningless running number. A deprecated id
 * is never recycled.
 *
 * ## SEC carries no level, and this pattern is what makes that true
 *
 * A security rule is weighed on the SEVERITY axis and ignores the level gate
 * entirely, so a level in its id names an axis it is not measured on. `SEC` is
 * therefore absent from the leveled alternative above: `SEC.L0.GRANT_PUBLIC` is
 * MALFORMED, not merely old, and the metadata property test over the whole
 * registry refuses it. That is deliberate — a convention holds until somebody
 * copies the neighboring file, and this one cannot be copied.
 *
 * Instead a security id names the QUESTION it asks, in one of five areas:
 *
 * - `SEC.CFG.<NAME>`  — is the SERVER configured safely? A setting, a GUC, a
 *   system variable: what the engine does regardless of who is connected.
 * - `SEC.AUTH.<NAME>` — how does somebody get IN? Credentials, password hashes,
 *   host matching, anonymous access, `pg_hba.conf` lines.
 * - `SEC.PRIV.<NAME>` — what may they do ONCE in? Grants, role attributes,
 *   ownership, the separation of runtime and migration connections.
 * - `SEC.RLS.<NAME>`  — does row-level security actually bite? Enablement,
 *   forcing, policies, and policies that are true for everyone.
 * - `SEC.INJ.<NAME>`  — did the APPLICATION hand the database a statement it
 *   assembled from a runtime value? The only area whose subject is PHP source
 *   rather than a live server, which is why it is the analyse suite's and reads
 *   nothing over a connection.
 *
 * - `SEC.PII.<NAME>`  — what does the STORED DATA expose on its own? A column
 *   whose name says personal data and whose storage says plain text. Its subject
 *   is a schema object rather than a server, an account, a grant or a policy, so
 *   none of the five above fits it and it does not fit them.
 *
 * ⚠️ `PII` and `PRIV` are two characters apart and mean opposite things —
 * personal data versus privileges. The longer spelling `PRIVACY` was rejected
 * for exactly that reason: `SEC.PRIV.*` beside `SEC.PRIVACY.*` is a pair a
 * reader mis-scans, and a suppression entry naming the wrong one silences a rule
 * nobody meant to silence.
 *
 * The area is decided by the SUBJECT a rule reads, not by the topic its name
 * evokes: `SEC.CFG.LOCAL_INFILE_FILE_GRANT` judges a server variable even though
 * its name says GRANT, and `SEC.PRIV.ROLE_BYPASSRLS` reads a role attribute even
 * though its name says RLS. Written as "fixed by configuration" instead of
 * "reads a server setting", the CFG boundary stops separating anything — several
 * AUTH and PRIV rules are also fixed by editing a file.
 *
 * Two reserved families sit outside every shape above, because neither describes
 * a strictness appetite nor asks one of those four questions:
 *
 * - `SEC.SKIPPED.<NAME>` — the security suite's degradation findings.
 * - `CAP.PRESCAN.<NAME>` — what the static pre-scan found in a migration BEFORE
 *   anything ran. A pre-scan hit is not a statement about SQL; it is the reason a
 *   migration is not captured at all, so it has no level to sit at.
 */
final class RuleIdFormat
{
    /**
     * @var list<string> the reserved area prefixes
     */
    public const array AREAS = ['PG', 'MY', 'SEC', 'GEN', 'CAP'];

    /**
     * The five questions a security rule can ask. Held here rather than in the
     * pattern alone so the guard over the registry and the documentation-url
     * derivation read the SAME list — two copies would drift, and the drift
     * would be invisible because both would stay green.
     *
     * `INJ` arrived late and for a measured reason. The scheme was fixed with
     * four areas while the injection family existed only in planning, and the
     * first rule of that family then shipped as `SEC.INJ.RAW_SQL_WITHOUT_REASON`
     * — an id this contract REJECTED. Nothing went red, because the rule was in
     * no registry, and the property test only ever sees ids the registry carries.
     * Two gaps, one silence: an id nobody validated because a rule nobody listed.
     *
     * `PII` arrived the same way and deliberately NOT the same way: the privacy
     * pack's column rule needed a sixth area because its subject
     * is a schema object, and it was added HERE first — so the id was valid the
     * moment the rule existed rather than after somebody noticed.
     *
     * @var list<string>
     */
    public const array SECURITY_AREAS = ['CFG', 'AUTH', 'PRIV', 'RLS', 'INJ', 'PII'];

    /**
     * `<AREA>.L<n>.<NAME>` for a leveled rule, `SEC.<AREA>.<NAME>` for a security
     * rule, or one of the two reserved families.
     *
     * SEC is absent from the leveled alternative on purpose; see the class note.
     */
    public const string PATTERN = '/^(?:(?:PG|MY|GEN|CAP)\.L\d\.[A-Z][A-Z0-9_]*|SEC\.(?:CFG|AUTH|PRIV|RLS|INJ|PII)\.[A-Z][A-Z0-9_]*|SEC\.SKIPPED\.[A-Z][A-Z0-9_]*|CAP\.PRESCAN\.[A-Z][A-Z0-9_]*)$/';

    /** Whether the rule id matches the scheme. */
    public static function matches(string $ruleId): bool
    {
        return preg_match(self::PATTERN, $ruleId) === 1;
    }

    /**
     * Whether a SUPPRESSION may name this id — a wider question than {@see matches()}, and the
     * difference is whose naming scheme is being judged.
     *
     * ## Two questions that were answered by one predicate, and it cost the wrong one
     *
     * `matches()` says how a rule of THIS package may be called. It is the catalog's guard, it is
     * public API from 1.0, and it must stay exactly as strict as it is.
     *
     * A suppression names something else entirely: it may name a rule an EXTERNAL TOOL emits, and
     * those ids follow the tool's scheme, not ours. Squawk prints `prefer-timestamp-tz` — lowercase,
     * hyphenated — and the Postgres Language Server prints its own shapes. Judging those against our
     * scheme refuses them all.
     *
     * Measured before this existed: `SQUAWK.ban-drop-table`, a rule the SHIPPED MAP describes, was
     * refused by the configuration schema before any run started — while `PG.L1.NO_RULE_ANSWERS_TO_THIS`,
     * a pure typo in our own scheme, was admitted. The two answers were exactly the wrong way round.
     *
     * ## What this checks, and what it deliberately leaves to the validator
     *
     * SHAPE only: a namespace segment in our own casing, a dot, and a non-empty remainder that
     * carries no whitespace. Whether anything answers to the id — and whether its namespace belongs
     * to a tool this build ships an adapter for — is {@see RuleIdValidator}'s
     * question, because only it can see the drivers. A shape check that tried to know the tools
     * would be a second list of them, going stale on its own schedule.
     */
    public static function matchesSuppressionTarget(string $ruleId): bool
    {
        return self::matches($ruleId) || preg_match('/^[A-Z][A-Z0-9_]*\.[^\s]+$/', $ruleId) === 1;
    }

    /**
     * Whether the id belongs to the reserved `SEC.SKIPPED.*` family — the
     * security suite's degradation findings (a check that could not run, reported
     * as undetermined, never swallowed as a pass).
     */
    public static function isSkipped(string $ruleId): bool
    {
        return str_starts_with($ruleId, 'SEC.SKIPPED.');
    }

    /**
     * Whether the id belongs to the reserved `CAP.PRESCAN.*` family — a static
     * pre-scan hit, which is why a migration was never captured rather than a
     * judgment about the SQL it would have produced.
     */
    public static function isPreScan(string $ruleId): bool
    {
        return str_starts_with($ruleId, 'CAP.PRESCAN.');
    }
}
