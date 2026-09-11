<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Audit\ServerLifetime;
use Pushery\SQLens\Rules\CatalogVerdicts;

/**
 * A rule whose subject is the SERVER, or the role the audit connects as — not the schema.
 *
 * ## Why the rule declares this and nothing else can derive it
 *
 * The distinction looks like it could be read off a rule id: `SEC.CFG.*` is the server, `SEC.RLS.*`
 * is the schema. It cannot, and a prefix list would be wrong within a release. `SEC.PRIV.*` holds
 * both — `SEC.PRIV.ROLE_SUPERUSER` is an attribute of the connecting role, while
 * `SEC.PRIV.GRANT_TO_PUBLIC` is a grant on a table the migrations created and is as real on a
 * container as anywhere. A rule knows which of the two it is; an id does not.
 *
 * The same argument {@see DeclaresConfigurationReach} makes for its own axis: a second model of the
 * rule set would agree for a while and then be confidently wrong about one rule, which is worse than
 * the silence it replaced.
 *
 * ## What implementing it costs a rule, and what it must not cost
 *
 * Nothing about its verdict. A rule that implements this judges exactly as it did — the declaration
 * is read by {@see CatalogVerdicts} AFTER the rule has spoken, and only when
 * the project declared {@see ServerLifetime::Disposable}. A rule may not consult the lifetime
 * itself: two places deciding one thing is two places to disagree, and the rule would then be
 * answering a question about the run instead of about its subject.
 *
 * ## The phrase is prose because a reader reads it
 *
 * The finding that replaces the flagged one has to say WHAT went unjudged, in the words of the thing
 * rather than the id of the rule. "this server's host-based authentication file" tells an operator
 * where to look on the target host; `SEC.AUTH.HBA_TRUST` tells them to go and look up a rule id
 * first.
 */
interface JudgesTheServerItRunsOn
{
    /**
     * What this rule judges, as a noun phrase that fits after "on a disposable server, ".
     *
     * A phrase, not a sentence: the renderer puts it inside one, and a rule that punctuated its own
     * would show up mid-line with a full stop in it.
     */
    public function serverSubjectJudged(): string;
}
