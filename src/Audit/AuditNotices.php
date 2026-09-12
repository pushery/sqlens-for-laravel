<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use LogicException;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\Degradation\CatalogNotice;
use Pushery\SQLens\Catalog\InstanceIdentity;
use Pushery\SQLens\Catalog\PoolerReading;
use Pushery\SQLens\Catalog\Security\SecurityNotice;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Config\ConfigViolation;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\DriverResolutionReason;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Rules\RuleDeprecation;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The things an audit reports that no RULE found — every one of them a reason the run is not simply
 * clean.
 *
 * They are findings rather than log lines on purpose. A deploy pipeline reads the JSON and branches
 * on it; anything that only reached the console would be invisible to the thing actually making the
 * decision. And each is `undetermined` rather than a failure, because none of them says the schema
 * is wrong — they say the run could not fully answer, which is the third value this package exists
 * to keep.
 */
final readonly class AuditNotices
{
    /** The prefix every audit-run notice reports under, so a reader can tell them from rule findings. */
    public const string PREFIX = 'sqlens.audit';

    /**
     * Nothing was checked, and that must not look like nothing was wrong.
     *
     * A level and category combination admitting no rule is easy to produce by accident — `--level=1
     * --category=idiom` has no members — and its output is otherwise identical to a clean audit of a
     * healthy database.
     *
     * @param  list<string>|null  $categories
     */
    public static function noActiveRules(int $level, ?array $categories, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::NoActiveRules->id(),
            sprintf(
                'No audit rule is active at level %d%s, so nothing about %s was checked. This is not a clean '
                .'result: widen the level or the category scope, or remove the filter.',
                $level,
                $categories === null || $categories === [] ? '' : ' in the categories '.implode(', ', $categories),
                $target->connection,
            ),
            UndeterminedReason::NoActiveRules,
            $target,
            $context,
        );
    }

    /**
     * More than one read host, and nothing said which — refused before anything connected.
     *
     * Named as its own notice rather than folded into the ambiguous-CONNECTION one, because the two
     * are answered with different flags: `--connection` picks a connection, `--host` picks a host
     * within one. A consumer handed the wrong sentence goes looking in the wrong config block.
     *
     * @param  list<string>  $hosts
     */
    public static function ambiguousReadHosts(array $hosts, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::AmbiguousReadHosts->id(),
            sprintf(
                'The connection configures more than one read host (%s) and nothing said which to audit. '
                .'Laravel picks one at RANDOM — it shuffles the list and chooses the read and write '
                .'sides independently — so two runs of this unchanged project would reach different '
                .'servers, and the difference between a primary and a replica would read as drift in a '
                .'report that never said which one answered. Name one with --host, or set '
                .'sqlens.host.',
                implode(', ', $hosts),
            ),
            $runContext,
        );
    }

    /**
     * A host was pinned that the configuration does not offer.
     *
     * Refused rather than obeyed: connecting anyway would audit a server the project never
     * configured, and reporting that as the project's database is worse than not running.
     *
     * @param  list<string>  $offered
     */
    public static function unofferedHost(string $pinned, array $offered, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::UnofferedHost->id(),
            sprintf(
                'The host "%s" was named, and this connection does not configure it%s. Connecting to it '
                .'anyway would audit a server the project never configured and report it as the '
                .'project\'s database, which is worse than not running at all.',
                $pinned,
                $offered === [] ? '' : ' — it offers '.implode(', ', $offered),
            ),
            $runContext,
        );
    }

    /**
     * The server's own configuration could not be read at all.
     *
     * Every server-baseline rule then has no subject, and a rule with no subject reports nothing —
     * which is byte-for-byte what a correctly configured server produces. Without this notice the
     * two are indistinguishable, and the more alarming of them is the one that looks clean.
     *
     * Distinct from a per-variable refusal, which the rules themselves report: this says the reading
     * as a whole did not happen, so it is stated once rather than once per rule that went hungry.
     */
    public static function settingsUnreadable(UndeterminedReason $reason, ?string $detail, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::SettingsUnreadable->id(),
            sprintf(
                'The server settings of %s could not be read (%s)%s, so every server-baseline check was '
                .'left without anything to judge. Their silence in this report means "not checked", not "fine".',
                $target->connection,
                $reason->value,
                $detail === null || $detail === '' ? '' : ': '.$detail,
            ),
            $reason,
            $target,
            $context,
        );
    }

    /**
     * Something in scope went unread, carried out of the snapshot and into the report.
     *
     * The skip already knows why it happened; this only moves it where a consumer can see it. A skip
     * that stayed inside the snapshot would make an incomplete audit and a complete one produce the
     * same output.
     */
    public static function skipped(CatalogSkip $skip, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            // The REGISTERED family, `AUDIT.CATALOG.UNREAD.<reason>`, rather than the bare literal
            // `CAP.L0.CATALOG_SKIPPED` this used to write. That literal appeared in one file, was in
            // no registry and had no page behind the link it shipped — while `CatalogNotice` was
            // exported in `rule-registry.json` as a notice the tool can emit, and nothing emitted
            // it. The registry advertised one id and the reports carried another.
            CatalogNotice::idFor($skip->reason),
            sprintf(
                '%s was not read (%s)%s. Whatever a rule would have said about it is unknown, not fine.',
                $skip->reference,
                $skip->reason->value,
                $skip->detail === null ? '' : ': '.$skip->detail,
            ),
            // The reason the SkipReason itself names. This used to collapse every incomplete
            // reading onto `catalog_read_failed`, so a missing GRANT and a dropped socket were
            // machine-identical — one is fixed with a GRANT, the other by looking at the server.
            $skip->reason->undeterminedReason(),
            $target,
            $context,
            $skip->reference,
            // Every reason shares one page: what a reader needs to know is the same in all of them,
            // and a page per reason would be one sentence written seven times and maintained none.
            CatalogNotice::CatalogUnread->documentationUrl(),
            null,
            // The kind the skip itself names. It was dropped here, so an index that went unread
            // reported as a table -- and the reader who found sixteen of them had no way to see
            // that they were all indexes without opening each one.
            $skip->type,
        );
    }

    /**
     * Part of the SECURITY reading was refused, carried out of the reading and into the report.
     *
     * The one shape this whole family exists for: on a managed instance the connecting account
     * routinely cannot read parts of the security catalog, and a run that answered "no findings"
     * from a reading it was refused would be indistinguishable from a run that looked and found
     * nothing. The more alarming of those two is the one that looks clean.
     *
     * Reported per AREA rather than once per run: `pg_authid` withheld and `pg_policy` withheld are
     * different gaps with different fixes, and one collapsed sentence would name neither.
     */
    public static function securitySkipped(CatalogSkip $skip, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            SecurityNotice::idFor($skip->reference),
            sprintf(
                'the security reading could not cover %s (%s)%s. Every check that would have judged it '
                .'is unanswered, not clean — on a managed instance this is the ordinary state, and it '
                .'is stated rather than hidden so nobody reads the rest of this report as a complete '
                .'security answer.',
                $skip->reference,
                $skip->reason->value,
                $skip->detail === null ? '' : ': '.$skip->detail,
            ),
            $skip->reason->undeterminedReason(),
            $target,
            $context,
            $skip->reference,
            // One page for the family, like the catalog notices: what a reader needs to know is the
            // same for every area, and a page per catalog would be one sentence written eight times.
            SecurityNotice::SecuritySkipped->documentationUrl(),
            Category::Security,
            // Same as the catalog skip above: the reading knows what it could not cover.
            $skip->type,
        );
    }

    /**
     * The server is not the one the configuration describes.
     *
     * Reported rather than reconciled: SQLens cannot know which of the two is right. What it can do
     * is refuse to let a report about one instance be read as a report about another.
     */
    public static function instanceDivergence(InstanceTarget $target, SubjectContext $context): Finding
    {
        $parts = [];

        foreach ($target->divergences() as $field => $pair) {
            $parts[] = sprintf('%s configured %s, server says %s', $field, $pair['configured'], $pair['observed']);
        }

        return self::notice(
            AuditNotice::InstanceDivergence->id(),
            sprintf(
                'The connection "%s" does not describe the server that answered: %s. The findings below are '
                .'about the server, not about the configuration — confirm you audited the instance you meant.',
                $target->connection,
                implode('; ', $parts),
            ),
            UndeterminedReason::ConnectionNotConfigured,
            $target,
            $context,
        );
    }

    /**
     * The server that answered is not the one that was pinned.
     *
     * A hard stop rather than a note. Every finding a run like this produced would be about a
     * database nobody chose, while looking exactly like a report about the right one — so there is
     * nothing useful to be done with the rest of the run.
     */
    public static function divergentPin(InstanceTarget $target, SubjectContext $context): Finding
    {
        // Both halves read off the target once, because the notice's whole job is to name them and a
        // sprintf that quietly rendered an empty string would produce `The host "" was pinned` —
        // a sentence that says nothing while looking like a sentence.
        $identity = $target->identity;

        return self::notice(
            AuditNotice::PinnedHostDiverged->id(),
            sprintf(
                'The host "%s" was pinned and the server that answered says it is "%s". The audit stopped: '
                .'the pin did not take effect, so every finding below it would describe a database nobody '
                .'chose while reading like a report about the one you meant. Check the connection\'s read '
                .'block and any proxy or pooler between this process and the server.',
                $target->pinnedHost ?? '',
                $identity instanceof InstanceIdentity ? $identity->host ?? '' : '',
            ),
            UndeterminedReason::ConnectionNotConfigured,
            $target,
            $context,
        );
    }

    /**
     * A pinned host that could not be confirmed against the server's own answer.
     *
     * Reported at every run that pins by name, on purpose. It is not noise: it is the difference
     * between "SQLens confirmed it read db2" and "SQLens asked for db2 and cannot prove it got it",
     * and only one of those two is something a report is entitled to imply.
     */
    public static function unverifiablePin(InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::PinnedHostUnverified->id(),
            sprintf(
                'The host "%s" was pinned and the server %s, so the two cannot be compared. The pin DID '
                .'take effect — it was written onto the connection this run built — but SQLens will not '
                .'resolve a name to check it, because a DNS lookup would put a second source of truth and '
                .'a network call inside a run that promises the same result for the same state. Pin a '
                .'literal address to have this confirmed rather than reported.',
                $target->pinnedHost ?? '',
                $target->identity instanceof InstanceIdentity && $target->identity->host !== null
                    ? sprintf('named "%s"', $target->identity->host)
                    : 'named no address at all (a local socket, or a managed database that withholds it)',
            ),
            UndeterminedReason::PinnedHostUnverifiable,
            $target,
            $context,
        );
    }

    /**
     * A deprecated rule did not run, and the report says which successor to reach for.
     *
     * ## Why this is a finding and not a log line
     *
     * The whole class says it at the top: a deploy pipeline reads the JSON and branches on it, so
     * anything that only reached the console is invisible to the thing making the decision. A
     * deprecation is precisely the case where that matters — the run gets QUIETER, and quieter is
     * what a clean run looks like.
     *
     * ## Why the successor is not optional prose
     *
     * "This rule is deprecated" tells a reader that something changed and nothing about what to do.
     * The successor id is the whole value of the notice, so when there is none the message says so
     * in words rather than trailing off: a rule retired without a replacement is a real answer, and
     * a reader who knows that stops looking for one.
     */
    public static function withheldByDeprecation(Rule $rule, InstanceTarget $target, SubjectContext $context): Finding
    {
        // Not nullable here, and the type system says so: this notice is only ever built from the
        // set `RuleRegistry::deprecated()` returns, which is defined by this value being present.
        // An `?? 'unknown'` fallback would be a branch no run can enter — which the analyzer reports
        // rather than tolerates, and which coverage would then name as an unreachable line.
        $deprecation = $rule->deprecation();

        if (! $deprecation instanceof RuleDeprecation) {
            throw new LogicException(sprintf(
                'withheldByDeprecation() was handed %s, which is not deprecated. The notice is built '
                .'from RuleRegistry::deprecated(), so reaching this means that set stopped meaning '
                .'what its name says.',
                $rule->id(),
            ));
        }

        return self::notice(
            AuditNotice::RuleWithheldByDeprecation->id(),
            sprintf(
                'The rule %s was not applied: it has been deprecated since %s%s. It stays resolvable '
                .'in a baseline, an ignore list and a suppression, so nothing you configured breaks '
                .'— but it checks nothing any more, and this run says so rather than simply getting '
                .'shorter.',
                $rule->id(),
                $deprecation->since,
                $deprecation->replacedBy === null
                    ? ' with no successor, so what it used to check is now unchecked'
                    : ' and is replaced by '.$deprecation->replacedBy,
            ),
            UndeterminedReason::StructurallyNotApplicable,
            $target,
            $context,
        );
    }

    /**
     * A rule the version gate held back — reported rather than simply absent.
     *
     * The whole point of a version window is that the rule set shrinks against an older server. A
     * shrinking set that says nothing is the silent green in its purest form: the report is shorter,
     * every remaining finding is true, and nothing anywhere says a check was not made. So each
     * withheld rule gets a line naming itself, its window, and the version that excluded it.
     *
     * The reason distinguishes the two ways it happens, because the fixes differ. A rule outside a
     * KNOWN version's window is structurally not applicable — nothing is wrong and nothing can be
     * done short of upgrading the server. A rule whose window could not be evaluated because the
     * version was unreadable is a gap in the reading, and that one is worth chasing.
     */
    public static function withheldByVersion(string $ruleId, string $reason, bool $versionKnown, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::RuleWithheldByVersion->id(),
            sprintf(
                'The rule %s was not applied: %s. Whatever it would have said about this database is '
                .'unknown, not fine.',
                $ruleId,
                $reason,
            ),
            $versionKnown
                ? UndeterminedReason::StructurallyNotApplicable
                : UndeterminedReason::ServerVersionUnresolvable,
            $target,
            $context,
        );
    }

    /**
     * A rule that cannot answer HERE — withheld because its verdict is about the write path and this
     * instance is not on it.
     *
     * One notice per withheld RULE, not per object. The rule was withheld for the whole run, and a
     * copy of the same sentence under every table would bury the findings that ARE about this
     * instance. It is a finding rather than a log line for the reason everything else in this class
     * is: a check that did not run and a check that passed produce the same silence otherwise, and
     * on a replica that silence would read as "the server settings are fine".
     */
    public static function withheldByInstanceScope(Rule $rule, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::InstanceScopeUnanswerable->id(),
            sprintf(
                'The rule %s was not applied: %s. Its answer would have described the instance that '
                .'answered rather than the write path it is about, and a report cannot tell those two '
                .'apart once the finding is written. Point the audit at the primary to have it checked.',
                $rule->id(),
                $rule->instanceScope()->withheldBecause($target->role()->value),
            ),
            UndeterminedReason::InstanceScopeUnanswerable,
            $target,
            $context,
        );
    }

    /**
     * The reading came through a connection whose statements may not share one server.
     *
     * Said once at run level, in addition to what each withheld rule reports for itself: fifteen
     * undetermined settings deserve one explanation of the cause, not fifteen copies of it.
     */
    public static function pooledConnection(InstanceTarget $target, SubjectContext $context): Finding
    {
        $pooler = $target->pooler;

        return self::notice(
            AuditNotice::ConnectionPooled->id(),
            sprintf(
                'The audit reached this database through a connection whose topology is %s, so every check '
                .'about the SERVER — its settings, its version-level configuration — is reported as '
                .'undetermined rather than judged. Behind a transaction pooler consecutive statements can '
                .'run on different backends, which makes a reading assembled from several of them describe '
                .'no single machine. Schema findings below are unaffected: a schema is the same on every '
                .'backend of one database. Point the audit at a direct connection to have the server '
                .'checked as well.',
                $pooler instanceof PoolerReading ? $pooler->describe() : 'unknown',
            ),
            UndeterminedReason::TransactionPooled,
            $target,
            $context,
        );
    }

    /**
     * More than one instance was plausible and nothing said which.
     *
     * @param  list<string>  $candidates
     */
    public static function ambiguousInstance(array $candidates, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::InstanceAmbiguous->id(),
            sprintf(
                'More than one supported connection is configured (%s) and none was chosen. Which instance an '
                .'audit reads is part of what its report asserts, so SQLens will not pick one: pass '
                .'--connection, or set sqlens.connection.',
                implode(', ', $candidates),
            ),
            $runContext,
        );
    }

    /**
     * A notice about the RUN rather than about an instance — built before anything connected.
     *
     * Extracted when the second one arrived. These carry no target, because the whole point is that
     * no instance was resolved, so they cannot use {@see self::notice()} — and three hand-built
     * copies of the same eleven arguments is three places for the location shape or the level to
     * drift apart, invisibly, because each reads correct on its own.
     */
    private static function runNotice(string $ruleId, string $message, RunContext $runContext): Finding
    {
        return Finding::undetermined(
            $ruleId,
            self::PREFIX,
            $message,
            UndeterminedReason::ConnectionNotConfigured,
            Location::inCatalog('unknown', 'unresolved', 'connection', SchemaObjectType::Table),
            Category::Safety,
            Level::Capturable,
            StabilityTier::Stable,
            RuleDocumentationUrl::for($ruleId),
            new SubjectContext(driver: 'unknown', profile: $runContext->profile->value, strictTools: $runContext->strictTools),
        );
    }

    /**
     * The engine behind the driver key is not the one the rules describe.
     *
     * MariaDB answers Laravel's `mysql` driver and does not share MySQL 8.4's semantics, so a
     * report produced against it would be confident, specific, and about another product. The
     * run stops here: "nothing was checked" is what the shipped message says in all seven
     * locales, and that is only true if nothing runs.
     */
    public static function unsupportedEngine(
        DriverResolutionFailure $failure,
        InstanceTarget $target,
        SubjectContext $context,
    ): Finding {
        return self::notice(
            AuditNotice::UnsupportedEngine->id(),
            sprintf(
                'The audit stopped without checking anything: %s. SQLens reasons about MySQL 8.4 semantics, '
                .'and applying those rules to an engine that does not share them would produce confident, '
                .'wrong advice — so it produced none. The supported engines are PostgreSQL and MySQL; '
                .'anything else is a declared non-goal rather than a gap.',
                $failure->detail,
            ),
            $failure->undeterminedReason(),
            $target,
            $context,
        );
    }

    /**
     * The instance this audit read is older than the floor its rules were written for.
     *
     * An `undetermined`, never a refusal. The owner's decision was that the run continues and
     * says unmistakably what its verdicts are worth: a qualified report is worth more than no
     * report, and refusing would withhold it from exactly the operators least able to judge a
     * schema for themselves.
     *
     * Both directions are stated, because the one-sided reading — "old server, so the tool is
     * being over-cautious" — misses the dangerous half. No rule was ever written for a version
     * below the floor, so a hazard that only exists there has nothing looking for it: a clean
     * audit on an unsupported instance is the least informative result this tool can produce.
     */
    public static function serverBelowFloor(
        DriverResolutionFailure $failure,
        InstanceTarget $target,
        SubjectContext $context,
    ): Finding {
        if ($failure->reason !== DriverResolutionReason::VersionBelowFloor) {
            // The attribution guard spoke instead of the floor — the banner names another
            // engine, or the driver's own declared minimum is unreadable. Reported rather than
            // dropped: silence here would be a silent green introduced BY the wiring meant to
            // prevent one.
            return self::notice(
                AuditNotice::ServerBelowFloor->id(),
                sprintf(
                    'Whether this instance meets the supported floor could not be judged: %s. The findings '
                    .'below were produced as usual, but nothing here establishes that these rules describe '
                    .'this server.',
                    $failure->detail,
                ),
                UndeterminedReason::UnknownServerVersion,
                $target,
                $context,
            );
        }

        return self::notice(
            AuditNotice::ServerBelowFloor->id(),
            sprintf(
                'SQLens supports %s and above; this instance reports %s. The audit ran and the findings below '
                .'are real, but they may be wrong in BOTH directions — a rule may flag behavior this server '
                .'does not have, and may stay silent about behavior it does, because no rule was written for a '
                .'version below the floor. A clean result here is not clearance. Upgrade the instance before '
                .'treating this report as authoritative.',
                $failure->placeholders['required'] ?? 'a supported version',
                $failure->placeholders['detected'] ?? 'an older version',
            ),
            UndeterminedReason::ServerBelowSupportedFloor,
            $target,
            $context,
        );
    }

    /**
     * The project pinned a server version, and the live instance is a different one.
     *
     * Reported rather than resolved, and reported rather than silently ignored — the two failure
     * modes this sits between. The audit deliberately gates its rules on the REAL version, because
     * it is talking to the machine the findings will be applied to; so the pin changed nothing
     * about this run, and saying nothing would leave a project believing the pin was honored.
     * Escalating it to a failure is a pre-deploy decision and is not made here. This layer's only
     * job is that nobody can fail to see it.
     *
     * The direction matters more than the disagreement. A pin BELOW the real version means the
     * project is developing against an older engine than it runs on — every rule the newer server
     * would have admitted was still applied here, which is right, and the lint runs on the same
     * project were not. A pin ABOVE it is the dangerous one: lint has been reporting against
     * capabilities the production server does not have.
     */
    public static function assumedVersionSkew(
        string $pinned,
        string $detected,
        InstanceTarget $target,
        SubjectContext $context,
    ): Finding {
        return self::notice(
            AuditNotice::AssumedVersionSkew->id(),
            sprintf(
                'This project pins assume_server_version to %s, and the audited instance reported %s. The '
                .'audit judged this run against %s, the version the server actually is, because that is the '
                .'engine these findings will be applied to — so the pin changed nothing here. It does change '
                .'what `sqlens:lint` reports on the same project, which reasons from the pin: every lint '
                .'result on this codebase describes a %s server. Align the pin with the instance, or state '
                .'deliberately why the two differ.',
                $pinned,
                $detected,
                $detected,
                $pinned,
            ),
            UndeterminedReason::AssumedVersionSkew,
            $target,
            $context,
        );
    }

    /**
     * A rule id in the audit ignore list that no rule answers to.
     *
     * A finding rather than an exception, so the run reports it the way it reports everything else
     * — with an id a pipeline can branch on and a message a person can act on. The exit code says
     * nothing was audited; this says exactly which line to fix, and offers the closest real id
     * without applying it. Rule ids are public API, so nothing here resolves a near-miss on the
     * project's behalf: a validator that helpfully accepted `pg.l2.concurrently` would make the id
     * set unknowable, and the next release that changed the folding would silently un-suppress
     * findings nobody chose to un-suppress.
     */
    public static function invalidIgnoreList(ConfigViolation $violation, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::InvalidIgnoreList->id(),
            $violation->message().' Nothing was audited: an ignore list that names a rule which does '
                .'not exist would silence nothing while looking set, and a rule believed to be off but '
                .'still firing is read past for months.',
            $runContext,
        );
    }

    /**
     * Object patterns in the ignore list that matched nothing this run read.
     *
     * A notice rather than an error, because a pattern may legitimately point at a table that does
     * not exist yet — and rather than silence, because an orphaned pattern is indistinguishable
     * from a working one: both produce a report without those findings. The only way a project
     * learns its ignore list has rotted is by being told.
     *
     * At level 0, which is what makes it level-INDEPENDENT rather than merely low. A diagnosis
     * hung off a high level would be filtered out of every realistic run — profile `local` or
     * `ci`, effective level 6 or 7 — and the guard would be an arm that never fires, reading as
     * green. Level 0 is in every cumulative gate there is.
     *
     * @param  list<string>  $patterns
     */
    public static function orphanedIgnorePatterns(array $patterns, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::OrphanedIgnore->id(),
            sprintf(
                'These ignore patterns matched nothing in the audited schema: %s. That is not an error — a '
                .'pattern may point at a table that does not exist yet, or at one somebody finally dropped — '
                .'but it is debt, and it is the kind nobody sees: an orphaned pattern and a working one '
                .'produce the same report. Delete the line, or keep it deliberately.',
                implode(', ', $patterns),
            ),
            $runContext,
        );
    }

    /**
     * The run was told to bypass the baseline, and this suite applies none.
     *
     * Reported rather than silently accepted, which is the whole difference between a flag and a
     * promise. `--ignore-baseline` says "show me everything the baseline is hiding"; a suite with
     * no baseline hides nothing, so the flag changes not one finding — and a report that came back
     * unchanged reads as "there was nothing hidden" rather than "nothing could have been". Those
     * are the same output and opposite facts.
     *
     * It goes away when the audit gains a baseline. Until then this is the honest shape: the
     * instruction was accepted, it had no effect, and the operator is told which of the two it was.
     */
    public static function baselineBypassHadNothingToBypass(RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::NoBaselineToIgnore->id(),
            'This run was asked to ignore the baseline, and no baseline was in force — so the flag '
                .'changed nothing rather than revealing nothing. The two look identical in a report, which '
                .'is why this says so. Either sqlens.baseline.path names no file, or the file it names is '
                .'missing or unreadable. Suppression from sqlens.audit.ignore is unaffected either way: '
                .'--ignore-baseline deliberately does not touch it.',
            $runContext,
        );
    }

    /**
     * The project looks multi-tenant and has not said which tenant this report is about.
     *
     * A refusal rather than a guess, and the guess is what makes it one. Auditing whichever
     * connection happened to be default produces a report about ONE tenant that is
     * indistinguishable from a report about the application — same header, same findings, same
     * exit code — so the reader draws a conclusion about their system from a statement about one
     * of their customers. There is no safe default here: every tenant is the wrong one to pick on
     * somebody's behalf.
     *
     * The message names the signals, because "this looks multi-tenant" without them is an
     * assertion the reader cannot check, and the heuristic is allowed to be wrong.
     */
    public static function tenancyNotDeclared(string $signals, RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::TenancyNotDeclared->id(),
            sprintf(
                'This project looks multi-tenant (%s) and sqlens.audit.tenancy.mode is still "none". An audit '
                .'across N tenant databases is not one statement, and auditing whichever connection happens to '
                .'be default produces a report about a single tenant that reads exactly like a report about the '
                .'application. Set mode to "explicit" and name the reference tenant, or set it to "none" '
                .'deliberately if these signals are wrong — the check is a heuristic and saying so is a valid '
                .'answer.',
                $signals,
            ),
            $runContext,
        );
    }

    /**
     * The project declared tenants and named none.
     *
     * Separate from the notice above because the two are different states: one project has not
     * answered the question, the other answered "explicit" and stopped halfway. Telling the second
     * that it "looks multi-tenant" would describe a discovery it already made.
     */
    public static function tenancyReferenceMissing(RunContext $runContext): Finding
    {
        return self::runNotice(
            AuditNotice::TenancyReferenceMissing->id(),
            'sqlens.audit.tenancy.mode is "explicit" and no reference tenant is named. An audit over several '
                .'tenant databases is not a single statement, so this run needs to know which tenant it is '
                .'about — the report says so in its header, and a finding that did not name its tenant would '
                .'be read as applying to all of them.',
            $runContext,
        );
    }

    /**
     * The connection could not be opened at all — nothing was audited.
     *
     * This used to be the only way a normal `sqlens:audit` run could end in an uncaught exception,
     * and every consequence of that was wrong in its own direction: exit code 1, which this
     * package's own contract defines as "findings breached a gate", so a CI reading exit codes
     * concluded that problems had been found in a database nobody reached; an `--output` file left
     * at zero bytes, which reads as a clean report; and the connection's host, port, database and
     * role rendered into the console and the host application's error log.
     *
     * As a notice it is the honest third value: named, in the report, counted as undetermined, and
     * carrying the driver's own words through the redactor so the reader can tell a wrong password
     * from a firewall without the message naming either machine.
     */
    public static function serverUnreachable(string $detail, InstanceTarget $target, SubjectContext $context): Finding
    {
        return self::notice(
            AuditNotice::ServerUnreachable->id(),
            sprintf(
                'The connection %s could not be opened, so NOTHING was audited — this report is empty because '
                .'the run never reached a database, not because the database is in good order. The driver said: '
                .'%s',
                $target->connection,
                $detail,
            ),
            UndeterminedReason::ServerUnreachable,
            $target,
            $context,
        );
    }

    /**
     * @param  string|null  $documentationUrl  the FAMILY page, for an id whose last segment varies;
     *                                         null derives the page from the id, which is the rule
     *                                         everywhere else and the one a guard enforces
     */
    private static function notice(
        string $ruleId,
        string $message,
        UndeterminedReason $reason,
        InstanceTarget $target,
        SubjectContext $context,
        ?string $objectName = null,
        ?string $documentationUrl = null,
        // Safety unless the caller says otherwise. A notice about the SECURITY reading is a security
        // statement — a project that suppresses what its managed provider withholds must be able to
        // do that without also silencing gaps in the schema reading, which is a different problem
        // with a different fix, and the category is what makes those two separable.
        ?Category $category = null,
        // What KIND of object this is about, when the caller knows. Null means the notice is about
        // the RUN rather than about one object -- there the name is the connection, and `Table` is
        // the placeholder those notices have always carried.
        //
        // A caller that DOES know used to lose it here: `CatalogSkip` has carried its
        // `SchemaObjectType` from the start, described in its own docblock as "the axis a reader
        // groups by", and this method replaced it with `Table` for every skip. A consumer read
        // sixteen index skips reported as tables, which is the one axis that would have let them
        // group the report at a glance.
        ?SchemaObjectType $objectType = null,
    ): Finding {
        return Finding::undetermined(
            $ruleId,
            self::PREFIX,
            $message,
            $reason,
            Location::inCatalog(
                $target->driver,
                $target->connection,
                $objectName ?? $target->connection,
                $objectType ?? SchemaObjectType::Table,
            ),
            $category ?? Category::Safety,
            Level::Capturable,
            StabilityTier::Stable,
            $documentationUrl ?? RuleDocumentationUrl::for($ruleId),
            $context,
        );
    }
}
