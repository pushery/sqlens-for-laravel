<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Whether the project has told SQLens which connection is the runtime one — and, when it has, whether
 * that is the same connection it deploys migrations with.
 *
 * A rule of its own rather than a branch inside {@see RuntimeDdlRule}, and the reason is what each of
 * them can say. The DDL rule judges a GRANT and needs a runtime role to attach the finding to; this
 * one judges the CONFIGURATION and speaks even when there are no grants at all — which is exactly the
 * case a silent suite would leave a project in: nothing configured, nothing judged, nothing said.
 *
 * The `undetermined` here is the honest kind. SQLens cannot tell which of a project's connections is
 * meant to be the safe one, and guessing would name the wrong role — sending somebody to revoke a
 * privilege their deploy depends on.
 */
final class UnseparatedConnectionsRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Accounts only — what this rule judges is an attribute of a role.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Role];
    }

    public function id(): string
    {
        return 'SEC.PRIV.CONNECTIONS_UNSEPARATED';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        // One verdict per RUN, not per object: this rule is about the configuration, and the run has
        // exactly one. It attaches to the role subject the audit connected as, which is the one
        // subject a run always has and the one a reader would look at anyway.
        if ($object->type !== SchemaObjectType::Role || $object->getBool('connection_role') !== true) {
            return [];
        }

        $runtime = $object->getString('runtime_connection');
        $migration = $object->getString('migration_connection');

        if ($runtime === null || $runtime === '') {
            return [RuleVerdict::undetermined(
                'SQLens cannot tell which connection this application serves requests with, so it '
                .'cannot check the one measure that matters most against SQL injection at the database '
                .'layer: a runtime role that cannot perform DDL. Set sqlens.security.runtime_connection '
                .'and sqlens.security.migration_connection. If the project genuinely uses one '
                .'connection for both, set them to the same name — that is a finding SQLens can report, '
                .'and a guess it will not make.',
                UndeterminedReason::NotConfigured,
            )];
        }

        if (in_array($migration, [null, '', $runtime], true)) {
            return [RuleVerdict::flag(sprintf(
                'the application serves requests and deploys migrations on the same connection (%s), so '
                .'its runtime role holds whatever DDL the migrations need. A SQL injection that reaches '
                .'a request can then change the schema rather than only the rows — it can leave a table, '
                .'a function or a trigger behind, which outlives the request. Add a second connection in '
                .'config/database.php whose role holds only DML, point the application at it, and keep '
                .'the DDL rights on the migration one.',
                $runtime,
            ))];
        }

        // ── TWO NAMES ARE NOT TWO IDENTITIES ────────────────────────────────────────────────────
        //
        // Everything above compares the names a project filed its connections under. A second entry
        // in config/database.php pointing at the same user, host and database is a separation that
        // exists on paper and nowhere else — and it is the most convincing shape this defect takes,
        // because somebody deliberately created that entry and believes the measure is in place.
        //
        // Three-valued, because the comparison can genuinely fail: credentials resolved from the
        // environment at runtime leave an analysis context with nothing to compare, and answering "these
        // are separate" there would certify a separation nobody could see.
        // The identities travel as subject attributes, like every other fact a rule judges: a rule
        // that reached for config itself could not be put into a state by a test, and the states
        // that matter here are exactly the awkward ones.
        $runtimeIdentity = $object->getString('runtime_identity');
        $migrationIdentity = $object->getString('migration_identity');

        $sharesIdentity = $runtimeIdentity === null || $runtimeIdentity === ''
            || $migrationIdentity === null || $migrationIdentity === ''
                ? null
                : $runtimeIdentity === $migrationIdentity;

        return match ($sharesIdentity) {
            true => [RuleVerdict::flag(sprintf(
                'the application names two connections (%s and %s) that authenticate as the same '
                .'identity (%s), so the separation exists in config/database.php and nowhere else: '
                .'requests are still served by the account the migrations run as, holding whatever '
                .'DDL they need. Give the migration connection its own database user and leave the '
                .'DDL rights only there — a second entry pointing at the same credentials buys the '
                .'application nothing.',
                $runtime,
                $migration,
                (string) $runtimeIdentity,
            ))],

            null => [RuleVerdict::undetermined(sprintf(
                'the application names two connections (%s and %s), but this run cannot resolve who '
                .'they authenticate as, so it cannot tell whether they are the same identity. '
                .'Credentials resolved from the environment at runtime look like this. Two names '
                .'are not two identities, and reporting a pass here would certify a separation '
                .'nobody could see.',
                $runtime,
                $migration,
            ), UndeterminedReason::NotConfigured)],

            false => [],
        };
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the project\'s CONFIGURATION, not its behavior: a project that names one connection and uses two roles through it is separated in practice and reported here anyway',
            'cannot tell an unset value from a deliberate decision that one connection is right — a small application with a single role is a legitimate shape, and this finding is the prompt to say so rather than a verdict that it is wrong',
        ];
    }
}
