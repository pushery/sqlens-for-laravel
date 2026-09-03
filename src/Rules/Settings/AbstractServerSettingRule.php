<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Settings;

use Override;
use Pushery\SQLens\Catalog\CrossFactState;
use Pushery\SQLens\Catalog\PoolerVerdict;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Contracts\ChecksServerSetting;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\InstanceScope;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The base every server-baseline rule sits on: it owns the three-valued reasoning, the subclass
 * owns only what counts as an acceptable value.
 *
 * ## Why the honesty lives here and not in each rule
 *
 * Judging a server variable has four ways to be unable to answer, and every one of them is a way to
 * report a false pass:
 *
 * 1. The matrix has no entry for this variable on this server version.
 * 2. The reading never named the variable.
 * 3. The server named it and withheld the value.
 * 4. The variable is worth reading but deliberately not worth judging.
 *
 * Seventeen rules each writing that ladder is seventeen chances to collapse one rung into "looks
 * fine". Written once, a subclass cannot skip it: the only thing it is handed is a value the base
 * has already established is real and judgeable.
 *
 * ## Why it reads the server's value and never the session's
 *
 * Laravel sets `sql_mode` and the timezone on every MySQL connection, and SQLens bounds its own
 * session's timeouts. A rule reading what the connection is running with would therefore report the
 * framework's and the audit's own choices back to the project as its production configuration —
 * confidently, and with no test failing. The subject carries both; this base hands the subclass only
 * `server_value`, so the wrong one is not in reach.
 */
abstract class AbstractServerSettingRule extends AbstractCatalogRule implements ChecksServerSetting, DeclaresJudgedObjectTypes
{
    /**
     * Server variables only. The family narrows twice — first to this type, then to one variable name —
     * and a rule whose variable the reading never named is exactly the case the evaluated set exists
     * to separate from a variable that was read and found acceptable.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Setting];
    }

    private ?ServerSettingMatrix $matrix = null;

    /**
     * The matrix, read once per rule instance.
     *
     * Injectable so a test can hand in a matrix built for the case under test, and lazily defaulted
     * to the shipped file so the ordinary registration stays the one-argument shape every other rule
     * family uses. Not a constructor parameter with a default: {@see ServerSettingMatrix} is built
     * from a file through a named constructor, and a default expression cannot read one.
     */
    final protected function matrix(): ServerSettingMatrix
    {
        return $this->matrix ??= ServerSettingMatrix::bundled();
    }

    /** Hand this rule a matrix other than the shipped one — for tests that need a controlled entry. */
    final public function withMatrix(ServerSettingMatrix $matrix): static
    {
        $clone = clone $this;
        $clone->matrix = $matrix;

        return $clone;
    }

    /**
     * Whether this value is acceptable — the one judgment a subclass makes.
     *
     * Handed a value the base has established the server really reported, and the matrix entry that
     * applies to this server's version. Returns null when the value is fine, or the sentence that
     * says what is wrong with it.
     *
     * The subject rides along for {@see self::crossFact()} ONLY. It deliberately does not widen what
     * a rule may JUDGE: the session value is on that subject too, and a rule reading it would report
     * the audit's own connection as the server's configuration — the exact trap this family is built
     * to avoid. The guard for that is a test, not a promise.
     */
    abstract protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string;

    /**
     * Why this value cannot cause harm here, or null when nothing excludes it.
     *
     * The rare shape a silent pass would misrepresent. Returning null is the ordinary answer and
     * means "nothing structural excludes this" — NOT "this is fine", which is what an empty
     * violation says. Keeping the two apart is the whole reason this is its own hook.
     */
    protected function reasonedPass(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        return null;
    }

    /**
     * A verdict that settles this finding before the value is judged, or null for "nothing applies".
     *
     * Null is the ordinary answer and the default, so the rules that judge a value on its own merits
     * — which is most of them — never mention this hook.
     *
     * It exists for a question that has to be answered BEFORE the value means anything, and whose
     * own answer may be unknown. {@see self::reasonedPass()} cannot serve that: it returns a
     * sentence, so its only possible verdict is `pass`, and a rule forced through it would have to
     * report "I could not tell" as "this is fine".
     */
    protected function precondition(SchemaObject $object): ?RuleVerdict
    {
        return null;
    }

    /**
     * Whether this rule judges the value itself, without the matrix having an expectation for it.
     *
     * False by default, so the matrix's abstention is the last word for every rule that reads its
     * verdict from there — which is all of them but the privacy family.
     *
     * An abstention says "this value cannot be judged FROM THE VALUE". `log_statement = all` is a
     * privacy problem on a production server and how people debug on a laptop, and no entry in a
     * shipped file can know which one it is looking at. A rule that supplies the missing fact — the
     * environment, in that case — is not what the abstention was protecting against, and overriding
     * it is then a statement about what the RULE knows rather than a weakening of the data.
     *
     * Returning true is therefore a claim, and one that carries its own duty: such a rule must not
     * read {@see ServerSettingExpectation::$expected}, because there is none. It judges from what it
     * brought.
     */
    protected function bringsOwnExpectation(): bool
    {
        return false;
    }

    /**
     * A server setting is a property of THIS machine. It reads fine on a replica — that is exactly
     * the trap — and the value it returns there describes a node that serves no writes. Narrowed
     * from the catalog default because the base class is right about schemas and wrong about this.
     */
    #[Override]
    public function instanceScope(): InstanceScope
    {
        return InstanceScope::Instance;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        // Audit only, and not by inheritance. A server variable has no migration to read it from, so
        // there is nothing for the lint suite to run this against.
        return [Suite::Audit];
    }

    /**
     * The cross-facts this rule needs before it can judge, by name.
     *
     * Declared rather than read opportunistically, so the base can enforce the one rule all five
     * fact-using rules share: a fact the collector could not measure produces `undetermined` with
     * its reason, never silence. A rule that read a fact ad hoc inside `violation()` would have to
     * remember that itself, five times, and the fifth would forget.
     *
     * @return list<string>
     */
    protected function requiredCrossFacts(): array
    {
        return [];
    }

    /** What the driver measured beside this variable, or null when there was nothing to find. */
    final protected function crossFact(SchemaObject $object, string $name): ?string
    {
        return $object->getString($name);
    }

    /**
     * Whether that fact is a real answer, a real absence, or a gap.
     *
     * A subject carrying no state at all reads as {@see CrossFactState::Unavailable}, which is the
     * cautious direction: a rule then reports it could not check rather than asserting an absence
     * nobody established.
     */
    final protected function crossFactState(SchemaObject $object, string $name): CrossFactState
    {
        return SettingCrossFacts::stateOn($object, $name);
    }

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Setting || $object->qualifiedName !== $this->settingVariable()) {
            // Not this rule's subject. No finding, no noise — "not applicable" is not a skip to
            // report, it is simply another rule's business.
            return [];
        }

        $expectation = $this->matrix()->for(
            $this->settingDriver(),
            $this->settingVariable(),
            $object->context()->serverVersion?->toString(),
        );

        if (! $expectation instanceof ServerSettingExpectation) {
            return [RuleVerdict::undetermined(
                sprintf(
                    'no expectation is on file for %s on this server version, so its value was read but not judged.',
                    $this->settingVariable(),
                ),
                UndeterminedReason::UnknownServerVersion,
            )];
        }

        if (! $expectation->isJudged() && ! $this->bringsOwnExpectation()) {
            // A deliberate abstention, not a gap: `lower_case_table_names` depends on the deployment's
            // filesystem, so a rule judging it would be wrong on half of them. Nothing to report.
            //
            // The second half of the condition is not an escape hatch from that reasoning, it is the
            // reasoning applied one level down. The matrix abstains where a value cannot be judged
            // FROM THE VALUE — `log_statement = all` is a privacy problem on a production server and
            // how people debug on a laptop, so a matrix entry claiming either would be wrong half
            // the time. A rule that supplies the missing fact is not the rule that abstention is
            // about, and it says so out loud rather than being assumed.
            return [];
        }

        // Provenance before value. A server-baseline rule's premise is that the value it judges came
        // from the instance the report names; behind a transaction pooler consecutive statements can
        // land on different backends, so the "global" and "session" halves of one reading may
        // describe two machines. The values still LOOK fine, which is precisely why this cannot be
        // left to a reader to notice.
        //
        // Placed after the abstention rung on purpose: a rule that was never going to judge this
        // setting has nothing to withhold, and reporting the topology from it would be noise on a
        // finding nobody was going to get.
        $pooler = PoolerVerdict::tryFrom((string) $object->getString('pooler'));

        if ($pooler !== null && $pooler !== PoolerVerdict::None) {
            return [RuleVerdict::undetermined(
                sprintf(
                    '%s was read through a connection whose topology is %s, so the value cannot be '
                    .'attributed to one server: consecutive statements may reach different backends, '
                    .'which makes the global-versus-session distinction this check rests on '
                    .'meaningless. Point the audit at a direct connection to have it judged.',
                    $this->settingVariable(),
                    $object->getString('pooler_signals') ?? $pooler->value,
                ),
                UndeterminedReason::TransactionPooled,
            )];
        }

        $serverValue = $object->getString('server_value');

        if ($serverValue === null) {
            return [RuleVerdict::undetermined(
                sprintf(
                    '%s could not be read from this server, so its value was not judged.',
                    $this->settingVariable(),
                ),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        // The shared rung for cross-facts, and the reason they are DECLARED rather than read ad hoc.
        // A fact the collector could not measure is not zero: a catalog that reports no affected
        // object because it was unreadable looks exactly like one with nothing to report, and a rule
        // that let that through would state an absence about a database it never examined.
        foreach ($this->requiredCrossFacts() as $fact) {
            if ($this->crossFactState($object, $fact) === CrossFactState::Unavailable) {
                return [RuleVerdict::undetermined(
                    sprintf(
                        '%s was read, but %s could not be measured alongside it%s, so this check would '.
                        'have had to assume what it could not see.',
                        $this->settingVariable(),
                        str_replace('_', ' ', $fact),
                        ($detail = $object->getString($fact.'_detail')) === null ? '' : ' ('.$detail.')',
                    ),
                    UndeterminedReason::tryFrom((string) $object->getString($fact.'_reason'))
                        ?? UndeterminedReason::CatalogReadFailed,
                )];
            }
        }

        // A precondition that settles the finding before the value means anything — and unlike
        // `reasonedPass()` below, it may answer with ANY verdict, `undetermined` included.
        //
        // That difference is the whole reason it exists. `reasonedPass()` can only say "fine", so a
        // rule whose precondition is unanswerable would have to spell "I could not tell" as "fine",
        // which is the silent pass this package refuses everywhere else. The privacy rules are the
        // case: `log_statement = all` is a finding in production, harmless in development, and
        // genuinely unknown when nothing places the environment — three answers, not two.
        //
        // Placed AFTER the readability rungs on purpose: answering a precondition about a value the
        // run could not read would be a statement about a database it never examined.
        $precondition = $this->precondition($object);

        if ($precondition instanceof RuleVerdict) {
            return [$precondition];
        }

        // Asked BEFORE the judgment, because a structural exclusion makes the judgment moot rather
        // than wrong: a default engine of MyISAM on a server where MyISAM is disabled entirely is a
        // setting that looks bad and cannot bite. One hook rather than a nullable violation, so a
        // rule cannot accidentally express "excluded" as "fine" and lose the sentence.
        $excluded = $this->reasonedPass($serverValue, $expectation, $object);

        if ($excluded !== null) {
            return [RuleVerdict::pass($excluded)];
        }

        $violation = $this->violation($serverValue, $expectation, $object);

        return $violation === null ? [] : [RuleVerdict::flag($violation)];
    }

    /**
     * How to say "and here is what it would take to change it" without proposing the impossible.
     *
     * `data_checksums` and `lower_case_table_names` are fixed when the cluster is initialized. A
     * remediation telling somebody to set one of them is advice they will follow for an afternoon
     * before discovering it cannot be done, so those get the honest sentence instead.
     */
    final protected function remediation(ServerSettingExpectation $expectation): string
    {
        return match ($expectation->changeable) {
            // `session` and `reload` differ in whether a CONNECTION may also override the value —
            // not in what it takes to change what the server hands out. Both are a configuration
            // change plus a reload, and saying "a session can set it" to somebody holding a
            // server-baseline finding answers a question they did not ask: they need the server
            // fixed, not a workaround one connection at a time.
            SettingChangeCost::Session, SettingChangeCost::Reload => 'changing what the server hands new connections is a configuration change plus a reload — no downtime.',
            SettingChangeCost::Restart => 'changing it takes a server restart, so it needs a maintenance window.',
            SettingChangeCost::Initdb => 'it was fixed when the cluster was initialized and cannot be changed on this one — moving it means a new cluster and a dump/restore.',
        };
    }
}
