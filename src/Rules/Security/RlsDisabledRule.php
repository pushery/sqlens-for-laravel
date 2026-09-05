<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A table the project says holds tenant data, with row-level security switched off.
 *
 * Every row of it is visible to every role that holds `SELECT` — which, in an application that
 * separates tenants in the WHERE clause, is the entire dataset one forgotten clause away. The
 * separation exists in the application and nowhere in the database, so nothing catches the query that
 * omits it: not a test, not a review, not the database.
 *
 * ## Why this rule never guesses which tables those are
 *
 * "Which tables hold tenant data" is a question only the project can answer, and answering it by
 * heuristic produces a finding for every reference table, job queue and migration ledger in the
 * schema — a report nobody finishes, from a tool that has learned nothing about the application. So
 * the scope comes from `sqlens.security.rls`, and a project that has not set it gets ONE
 * `undetermined` naming the key rather than a silent pass or a page of guesses.
 *
 * That `undetermined` is the point rather than a formality. A security suite that says nothing about
 * RLS on a database with no RLS configured is indistinguishable from one that checked and found
 * everything in order, and those two reports must never look the same.
 *
 * ## What it says when row-level security cannot help
 *
 * An account with `BYPASSRLS` — or a superuser, which bypasses it by definition — reads every row
 * whatever the policies say. Telling a project to enable RLS without mentioning that would be
 * promising a protection one of its accounts still walks straight through, so the finding names those
 * accounts and points at `SEC.PRIV.ROLE_BYPASSRLS`, which is the finding that gets them fixed.
 *
 * ## Why it declares no version floor
 *
 * PostgreSQL has had row-level security since 9.5, and it is tempting to write that down. It would be
 * wrong here: the version window has no engine dimension, so a 9.5 floor would gate this rule OFF
 * against MySQL 8.4 and print a notice claiming the server is too old for a feature it does not have
 * in any version. The package's own floor is PostgreSQL 18, so a 9.5 window could never bind on the
 * engine it is about — it would only ever misfire on the other one. Silence on MySQL is instead a
 * property of the DATA: {@see RlsReading::unsupported()} produces no
 * table subjects and marks the reading unsupported, and this rule says nothing.
 */
final class RlsDisabledRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Both, deliberately: the rule judges the TABLE's row-level security, and reads the reading's own
     * state off a role subject so a refused reading is reported rather than read as "RLS is fine".
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Role, SchemaObjectType::Table];
    }

    /**
     * `SEC.RLS.DISABLED`, not the `SEC.PG.RLS.DISABLED` of the plan's ticket.
     *
     * The scheme is `<AREA>.L<n>.<NAME>` and machine-enforced; `SEC` is the area for the security
     * family, which is also why the rule lives in Core rather than under the PostgreSQL pack — that
     * pack's completeness guard refuses a security-category rule, because a severity-gated rule filed
     * in a level-gated set would bypass the gate the set is measured by.
     */
    public function id(): string
    {
        return 'SEC.RLS.DISABLED';
    }

    /**
     * Level 0: a security finding is weighed on the RISK axis, so its level says only "no run excludes
     * it". A project that wants fewer security findings raises `security.min_severity`, which is one
     * dial stated once — rather than a level that would quietly take the whole category with it.
     */
    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * `high`, and the reason is what the finding means rather than how often it fires.
     *
     * The project has stated that this table separates tenants. RLS being off makes that statement
     * false at the database layer, and the failure mode is not a crash but a query returning rows it
     * should never have seen — to a user, silently, with no error anywhere. There is no severity below
     * this for "the isolation you configured does not exist".
     */
    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type === SchemaObjectType::Role) {
            return $this->judgeScope($object);
        }

        if ($object->type !== SchemaObjectType::Table || $object->getBool('rls_scoped') !== true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the row-level security state of %s could not be read, so whether its rows are separated is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($object->getBool('rls_enabled') === true) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }

    /**
     * The one thing this rule says when the project named no tables at all.
     *
     * Attached to the role subject the audit connected as, because that is the one subject every run
     * has: a project that configured nothing produces no table subjects, and a rule with nothing to
     * judge would report nothing — the silent green in its purest form. One verdict per run, not one
     * per role, which is what the `connection_role` check makes it.
     *
     * @return list<RuleVerdict>
     */
    private function judgeScope(SchemaObject $object): array
    {
        // MySQL has no row-level security in any version, so there is nothing here for this check to
        // look at — and that is a different statement from "checked and fine". Telling a MySQL
        // project to CONFIGURE row-level security would indeed send somebody looking for a feature
        // that does not exist; saying the feature does not exist does the opposite, and stops a
        // reader inferring from an absent finding that tenant separation was examined.
        //
        // This rule alone carries it. The other five in the family judge TABLE subjects, and an
        // engine without row-level security produces none — so they are silent by construction
        // rather than by choice, and adding a statement to each would repeat one fact six times.
        // Gated on `connection_role` for the same reason the not-configured arm below is: the flag
        // rides every ROLE subject, and a server has several — measured, six on the MySQL test
        // instance. The statement is about the RUN, so it is made once, on the one role the audit
        // actually connected as.
        if ($object->getBool('rls_supported') !== true) {
            if ($object->getBool('connection_role') !== true) {
                return [];
            }

            return [RuleVerdict::notApplicable(
                'this server is MySQL, which has no row-level security at all, so none of the SEC.RLS.* '
                .'checks has anything here to look at. Reported rather than left silent, because an absent '
                .'finding reads as a check that passed. Tenant separation on this engine is an application '
                .'concern, and SQLens judges what the database can enforce.',
                NotApplicableReason::EngineLacksConstruct,
            )];
        }

        if ($object->getBool('connection_role') !== true) {
            return [];
        }

        // The project ANSWERED. `security.rls.mode = off` is the answer this rule's own remediation
        // offers, and until it produced a different report than silence the sentence was an
        // instruction that changed nothing: a project that followed it kept the same undetermined, at
        // severity high, on every run — and under --profile=ci kept a run it could not get green
        // except by waiving every undetermined at once.
        //
        // notApplicable rather than nothing, for the same reason the MySQL arm above is: an absent
        // finding reads as a check that passed, and "this database separates nothing" is a statement
        // worth having in the report.
        if ($object->getBool('rls_declined') === true) {
            return [RuleVerdict::notApplicable(
                'this project has set sqlens.security.rls.mode to off, which says that row-level '
                .'security is not how this database separates tenants. Nothing is judged here, and '
                .'that is an answer rather than a gap. If the answer changes — a tenant table arrives, '
                .'or separation moves into the database — name the tables in sqlens.security.rls.tables '
                .'or switch the mode to heuristic, and the SEC.RLS.* checks come back.',
                NotApplicableReason::DeclinedByProject,
            )];
        }

        if ($object->getBool('rls_configured') !== false) {
            return [];
        }

        return [RuleVerdict::undetermined(
            'SQLens does not know which tables in this database hold tenant data, so it cannot check '
            .'whether row-level security separates them — and a database where it does not is one '
            .'forgotten WHERE clause away from serving one tenant another one\'s rows. Name them in '
            .'sqlens.security.rls.tables, or set sqlens.security.rls.mode to heuristic and '
            .'sqlens.security.rls.tenant_column to the column that carries the tenant. If this '
            .'database genuinely separates nothing, set the mode to off — that is an answer SQLens can '
            .'record, and a guess it will not make.',
            UndeterminedReason::NotConfigured,
        )];
    }

    /**
     * The finding, with the part that is the same for everyone and the part that is about this server.
     *
     * `FORCE` is named alongside `ENABLE` rather than left to a second finding, because enabling
     * without forcing is the shape that looks fixed and is not: policies do not apply to the table's
     * OWNER, and an application connecting as the role that owns its tables — the ordinary Laravel
     * setup — reads every row with RLS switched on and a policy in place.
     */
    private function message(SchemaObject $object): string
    {
        $table = $object->qualifiedName;

        $message = sprintf(
            'row-level security is not enabled on %s, which this project lists as holding tenant data: '
            .'every row of it is visible to any role with SELECT, so the separation exists in the '
            .'application and nowhere in the database. ALTER TABLE %s ENABLE ROW LEVEL SECURITY, add a '
            .'policy that restricts rows to the current tenant, and ALTER TABLE %s FORCE ROW LEVEL '
            .'SECURITY as well — ENABLE alone does not apply to the table\'s owner, which is the role '
            .'a Laravel application usually connects as.',
            $table,
            $table,
            $table,
        );

        $bypassing = $object->getString('rls_bypassing_roles') ?? '';

        if ($bypassing === '') {
            return $message;
        }

        return $message.sprintf(
            ' Note that %s %s row-level security regardless of any policy, so enabling it here does '
            .'not restrict %s — see SEC.PRIV.ROLE_BYPASSRLS.',
            $bypassing,
            str_contains($bypassing, ',') ? 'bypass' : 'bypasses',
            str_contains($bypassing, ',') ? 'those accounts' : 'that account',
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the catalog, not the application: row-level security is a BACKSTOP, and a project whose every query filters by tenant is not exposed today. What it is exposed to is the query somebody writes next month without that filter, which this rule cannot see either',
            'judges the tables the project LISTED as tenant data, or the schema it named — a table nobody declared is invisible here, and the rule cannot tell an omission from a deliberate exclusion',
        ];
    }
}
