<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Audit\InstanceRole;

/**
 * What a rule's verdict is ABOUT — and therefore where that verdict is worth anything.
 *
 * ## The question this answers
 *
 * An audit run addresses one instance, and an instance is not the same kind of thing as a cluster
 * or a database. A rule that reports `max_connections` is describing THAT machine; a rule that
 * reports a foreign key without an index is describing a schema, which every node of the cluster
 * carries identically. Read on a replica, the first verdict is about a machine that serves no
 * writes — and the second is exactly as true as it would have been on the primary.
 *
 * Without the distinction there is only one behavior available, and both choices are wrong: run
 * every rule everywhere, and an instance-scoped finding gets acted on as if it described the system;
 * or withhold every rule off the primary, and an audit of a replica reports nothing at all about a
 * schema it can see perfectly well.
 *
 * ## Why it is a property of the RULE
 *
 * The instance's role is the other half of the pair, and {@see InstanceRole}
 * already answers it. Neither half decides alone: a replica is a fine place to judge a schema, and
 * a primary is a fine place to judge anything. Only the two together say whether a verdict can be
 * placed — which is why the scope belongs on the rule, where the author knows what their rule is
 * talking about, rather than being guessed per finding.
 */
enum InstanceScope: string
{
    /**
     * The whole cluster — a role, a grant, anything stored once and seen from every node.
     *
     * Answerable anywhere, because every node returns the same answer by construction.
     */
    case Cluster = 'cluster';

    /**
     * This machine and its write path — settings, timeouts, the seal on a session.
     *
     * The one scope that a replica cannot answer for. Not because the value is unreadable there —
     * it usually reads fine — but because the value it returns describes the replica, and a report
     * that presented it as the system's would be wrong in the most confident possible way.
     */
    case Instance = 'instance';

    /**
     * One database or schema — its objects, their shape, their keys.
     *
     * Answerable on any node that carries the database, which under physical replication is all of
     * them. A schema finding withheld on a replica would make a replica-targeted audit useless
     * without making it any safer.
     */
    case Database = 'database';

    /**
     * Whether a rule of this scope can be answered on an instance that is not the write path.
     *
     * The negative form is deliberate: this is asked in order to WITHHOLD, and a method named for
     * the permissive direction invites a caller to read a missing case as permission.
     */
    public function needsTheWritePath(): bool
    {
        return $this === self::Instance;
    }

    /** The reason line a withheld finding carries, naming the scope rather than restating the role. */
    public function withheldBecause(string $role): string
    {
        return sprintf(
            'this rule is scoped to the instance and its write path, and the instance that answered is %s',
            $role,
        );
    }
}
