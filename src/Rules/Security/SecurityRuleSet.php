<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Rules\Privacy\GeneralLogPersonalDataRule;
use Pushery\SQLens\Rules\Privacy\StatementLoggingRule;
use Pushery\SQLens\Rules\Privacy\UnencryptedColumnRule;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;

/**
 * The security rule family — the `SEC.*` area, composed like the lifecycle set and for the same
 * reason: one source, appended by every driver that can produce the subjects these rules judge.
 *
 * ## Why it is not part of a driver's own pack
 *
 * The PostgreSQL pack's completeness guard refuses a security-category rule in so many words, and it
 * is right to: a security rule is weighed on the SEVERITY axis, so one filed inside an engine's safety
 * pack would sit in a set whose whole contract is the level gate — and would bypass exactly the gate
 * that pack is measured by. Keeping the family in Core keeps the two axes apart where it counts.
 *
 * ## Why the rules are engine-neutral
 *
 * They judge the subjects the security readers produce, and both engines produce the same ones. A rule
 * that has nothing to say on an engine says nothing there without a driver check: MySQL has no PUBLIC
 * pseudo-role, so a grant subject read from MySQL simply never carries `to_public`. That is a stronger
 * arrangement than a per-driver list, because "this rule is silent on that engine" becomes a property
 * of the data rather than a line somebody has to remember to write.
 */
final readonly class SecurityRuleSet
{
    /** @var list<Rule> */
    public array $rules;

    /** @param  list<Rule>  $rules */
    public function __construct(array $rules = [])
    {
        usort($rules, static fn (Rule $a, Rule $b): int => $a->id() <=> $b->id());

        $this->rules = $rules;
    }

    /**
     * The shipped security set, built for one project root — so a finding's location is
     * repo-relative.
     *
     * Two rules need more than that. The patch-currency pair judges the server's version against
     * end-of-life data, and both of its extra dependencies are passed IN rather than reached for:
     *
     * - the advisory reader, because a rule that read configuration would have a verdict its own
     *   tests cannot see, and because the file is resolved once per run rather than once per rule;
     * - today's date, because a support window closes ON a date and a rule that read the clock
     *   would give two answers to one database across midnight, with nothing in the report to say
     *   which side it was on.
     *
     * Both default, and the defaults are the truth rather than a stub: an unconfigured project
     * reads the bundled file, which is exactly what {@see EolRepository::bundled()} does.
     */
    public static function forProjectRoot(string $projectRoot, ?EolRepository $advisories = null, ?string $today = null, ?RunEnvironment $environment = null, ?UnencryptedColumnEvaluator $privacyColumns = null): self
    {
        $advisories ??= EolRepository::bundled();
        $today ??= date('Y-m-d');

        return new self([
            // The privacy rules take the environment and NOTHING is defaulted in for it. Unlike the
            // advisory repository, whose bundled copy is what an unconfigured project genuinely
            // reads, there is no honest fallback for "which environment is this": a default would
            // have to pick production or not, and both answers are a guess about somebody's server.
            // Absent, the rules report `undetermined` — see AbstractPrivacySettingRule.
            new GrantToPublicRule($projectRoot),
            new ExcessiveGrantRule($projectRoot),
            new DefinerWithoutSearchPathRule($projectRoot),
            new BroadGrantScopeRule($projectRoot),
            new AdminPrivilegeInMigrationRule($projectRoot),
            new WildcardHostGranteeRule($projectRoot),
            new PasswordLiteralRule($projectRoot),
            new StatementLoggingRule($projectRoot, $environment),
            // The other half of each logging pair. One setting, two questions:
            // secrets in the log and personal data in it. They are gated by different
            // categories and usually by different people, so a single view is invisible to
            // whichever half did not select it — and a report missing a category reads as a
            // clean one.
            new GeneralLogPersonalDataRule($projectRoot, $environment),
            // The pack's only schema-reading rule. It is registered unconditionally like every
            // other one and admitted (or not) by PrivacyPack::admitted() — the switch lives in one
            // place, and a rule that gated itself would be a second answer to the same question.
            new UnencryptedColumnRule($projectRoot, $privacyColumns),
            new StatementLoggingSecretsRule($projectRoot),
            new PatchEolRule($projectRoot, $advisories, $today),
            new BypassRlsRoleRule($projectRoot),
            new CreateRoleAttributeRule($projectRoot),
            new HbaCleartextRule($projectRoot),
            new HbaMd5Rule($projectRoot),
            new HbaOpenCidrRule($projectRoot),
            new HbaParseErrorRule($projectRoot),
            new HbaTrustLocalRule($projectRoot),
            new HbaTrustRule($projectRoot),
            new PublicGrantRule($projectRoot),
            new RlsCheckAlwaysTrueRule($projectRoot),
            new RlsDisabledRule($projectRoot),
            new RlsNoPolicyRule($projectRoot),
            new RlsNotForcedRule($projectRoot),
            new RlsOwnerUnrestrictedRule($projectRoot),
            new RlsPolicyAlwaysTrueRule($projectRoot),
            new RoutineDefinerMutablePathRule($projectRoot),
            new RoutineDefinerRule($projectRoot),
            new RoutineDefinerUnsafePathRule($projectRoot),
            new RuntimeDdlRule($projectRoot),
            new SuperuserRoleRule($projectRoot),
            new DeprecatedPasswordHashRule($projectRoot),
            new DeprecatedPasswordHashLockedRule($projectRoot),
            // The other half of the account-credential question, and the sharper one: a deprecated
            // verifier still protects something, an absent one protects nothing. Paired on the same
            // locked/usable split for the same reason — severity is metadata on the rule.
            new NoPasswordRule($projectRoot),
            new NoPasswordLockedRule($projectRoot),
            // Where an account may arrive FROM, split on what it can do once it has. The host half of
            // a MySQL account name is an access control, and both rules are silent on PostgreSQL by
            // construction rather than by a check: a PostgreSQL role carries no host at all.
            new WildcardHostRule($projectRoot),
            new WildcardHostPrivilegedRule($projectRoot),
            // The privileges that administer the SERVER, from a shipped artifact rather than a list in
            // code — because MySQL split SUPER's powers across a family of dynamic privileges, and a
            // check for the old name alone is silent on a modern server.
            new AdminPrivilegeGrantRule($projectRoot),
            // The account with no NAME, split on whether it also has no password. It carries the
            // whole finding for that combination — the no-password pair above stands down on an
            // anonymous account, because one fact reported under two ids reads as two problems.
            new AnonymousAccountRule($projectRoot),
            new AnonymousAccountNoPasswordRule($projectRoot),
            // What an account may HAND ON, split on whether it hands on data access or the power to
            // reshape the schema. Engine-neutral by construction, unlike the two pairs above: both
            // readers already produce the grantable flag, from `GRANT OPTION` and from `is_grantable`.
            new GrantOptionRule($projectRoot),
            new GrantOptionStructuralRule($projectRoot),
            // The two privileges that reach PAST the database into the machine running it — one
            // writes files as the server process, the other reads everybody else's statements.
            // Neither is administrative, so neither belongs to the server-admin rule; both are
            // silent on PostgreSQL without a check, because that engine has no such privilege to
            // canonicalize.
            new FileGrantRule($projectRoot),
            new ProcessGrantRule($projectRoot),
            // The breadth of a grant rather than what it lets somebody hand on. Deliberately ONE
            // rule for both scopes: severity is metadata on the rule, so a global/database split
            // would be a second id for one fact — the difference goes in the message instead.
            new AllPrivilegesGrantRule($projectRoot),
            // The SERVER setting that decides how far the FILE privilege above reaches. Two findings
            // rather than one, deliberately: the grant is fixed by whoever manages accounts, the
            // setting by whoever manages the server, and either alone is worth acting on.
            new SecureFilePrivRule($projectRoot),
            // The other half of the file story, and it points the other way: secure_file_priv bounds
            // what the server may read on ITS disk, local_infile decides whether the server may ask
            // the CLIENT for a file. Neither implies the other.
            new LocalInfileRule($projectRoot),
            // Its escalation, and a second id rather than a second severity: severity is metadata on
            // the rule, and the two say different sentences — one about the server's capability, one
            // about what exists on this instance alongside it.
            new LocalInfileFileGrantRule($projectRoot),
            // Two more server variables, and both are findings about a GUARANTEE rather than about a
            // capability: one that statements are being written down verbatim, one that nothing
            // enforces the encryption the server already offers.
            new GeneralLogRule($projectRoot, $environment),
            new RequireSecureTransportRule($projectRoot),
            // The PostgreSQL counterpart, and a stronger statement than its MySQL neighbor: that one
            // reports a server that offers encryption without insisting on it, this one a server that
            // does not offer it at all.
            new TlsDisabledRule($projectRoot),
            new TlsMinVersionRule($projectRoot),
            // The only member of the md5 family that reports a server which is clean today. Its
            // siblings judge accounts and authentication rules that already carry the weak hash;
            // this one the setting that keeps producing new ones.
            new PasswordEncryptionRule($projectRoot),
            new UnseparatedConnectionsRule($projectRoot),
        ]);
    }

    /** @return list<Rule> */
    public function all(): array
    {
        return $this->rules;
    }
}
