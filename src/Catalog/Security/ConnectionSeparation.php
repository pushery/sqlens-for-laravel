<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Security;

/**
 * Which connection the application serves requests with, which one deploys migrations, and which role
 * each of those resolves to.
 *
 * It exists so the least-privilege rules can be judged in a test without a container: the alternative
 * is a rule that reaches into config and a database manager itself, which is a rule nobody can put
 * into a state — and the states that matter here are precisely the awkward ones (nothing configured,
 * both the same, a name that resolves to nothing).
 *
 * Every field may be null, and null MEANS something different in each: an unset connection name is a
 * question the project has not answered, and an unresolved role is a name that answers to nothing. The
 * rules tell those apart, which is why they are separate fields rather than one.
 */
final readonly class ConnectionSeparation
{
    public function __construct(
        /** The configured `security.runtime_connection`, or null when the project has not set it. */
        public ?string $runtime = null,
        /** The configured `security.migration_connection`, or null when the project has not set it. */
        public ?string $migration = null,
        /** The role the runtime connection authenticates as, when it could be resolved. */
        public ?string $runtimeRole = null,
        /**
         * Who the runtime connection actually is — `user@host/database`, or null when the
         * configuration does not say.
         *
         * Separate from {@see self::$runtime}, which is only the NAME under which a project filed
         * the connection. Two names are not two identities, and the gap between them is where the
         * measure this type exists to check quietly stops being taken.
         */
        public ?string $runtimeIdentity = null,
        /** The same for the migration connection: who it is, not what it is called. */
        public ?string $migrationIdentity = null,
        /**
         * The connection this RUN addressed, or null when it did not name one.
         *
         * The three fields above describe the project's configuration; this one describes the run
         * looking at it. Keeping them apart is the whole point — see {@see self::auditedIsRuntime()}.
         */
        public ?string $audited = null,
    ) {}

    /**
     * Whether this run is looking at the RUNTIME connection — three-valued, and the middle value is
     * the reason this exists.
     *
     * Everything else here is read off the configuration, and `runtimeRole` is filled from whichever
     * account the run authenticated as — unconditionally. So on a run made over the MIGRATION
     * connection, "the runtime role" silently means the migration role.
     *
     * Today's readers survive that: they compare a catalog row's GRANTEE against `runtimeRole`, find
     * no row, and stay quiet. False-negative, and nobody acts on silence. A rule that judges the
     * CONNECTING role itself inverts it — it would report the migration role as the runtime one and
     * tell somebody to revoke the privilege their deploy depends on. That is the failure
     * {@see self::isRuntimeGrantee()} already warns about in so many words.
     *
     * `null` means the question is not answerable: the run named no connection, or the project named
     * no runtime one. Answering `false` there would smuggle in a guess, and answering `true` would
     * smuggle in a worse one.
     */
    public function auditedIsRuntime(): ?bool
    {
        if ($this->audited === null || $this->audited === '' || $this->runtime === null || $this->runtime === '') {
            return null;
        }

        return $this->audited === $this->runtime;
    }

    /**
     * Whether a grant's grantee is the runtime role.
     *
     * False when the runtime role is unknown — not "maybe": a rule acting on a maybe would attach a
     * finding to whichever role happened to sort first, and name a fix for somebody else's account.
     *
     * @param  list<string>  $reachableFromRuntime  roles the runtime role holds the rights of through membership
     */
    public function isRuntimeGrantee(string $grantee, array $reachableFromRuntime = []): bool
    {
        // The runtime CONNECTION has to be declared, not just the role resolved. Without it the audit
        // still knows which account it authenticated as — but that account is not "the runtime role"
        // until somebody says so, and judging it anyway would be the guess this whole type exists to
        // avoid: on a run made over the migration connection it would name the wrong role, and the
        // finding would send somebody to revoke a privilege their deploy depends on.
        // MEMBERSHIP COUNTS, and it is not a refinement — the same sentence
        // {@see SecuritySubjects::ownedByConnection()} already makes about RLS ownership, applied to
        // the other half of the same question. `GRANT CREATE ON SCHEMA public TO app_writer` plus
        // `GRANT app_writer TO app` gives `app` the right to create; the grant row names
        // `app_writer`, so a comparison on the grantee's NAME answers no for the arrangement most
        // deploys actually have, and the rule stays silent about a runtime role that can rebuild the
        // schema.
        //
        // The reachable set is the CLOSURE the role reading already computes, so no second walk of
        // the membership graph happens here and the two cannot come to disagree.
        return $this->runtime !== null
            && $this->runtimeRole !== null && $this->runtimeRole !== ''
            && ($grantee === $this->runtimeRole || in_array($grantee, $reachableFromRuntime, true));
    }

    /**
     * Whether the application deploys migrations on the connection it serves requests with.
     *
     * True also when the migration connection is unset while the runtime one is set: a project that
     * named one and not the other is telling us it has one connection, and the finding for that state
     * is the same one — a runtime role that holds DDL because the deploy needs it.
     */
    public function runtimeIsMigration(): bool
    {
        return $this->runtime !== null && ($this->migration === null || $this->migration === $this->runtime);
    }
}
