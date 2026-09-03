<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Severity\Severity;

/**
 * What every security rule owes, whatever it judges.
 *
 * ## Why a contract and not a base class
 *
 * The obvious shape is one `AbstractSecurityRule` that the three subject families extend. PHP's
 * single inheritance forbids it: a rule over a schema object needs the catalog machinery, one over a
 * migration needs the migration machinery, and one over raw SQL needs a third — three different
 * parents for three subject kinds. A shared base class could only sit above all of them, which means
 * moving the subject machinery into traits and rebuilding `AbstractCatalogRule`, a class the whole
 * package leans on and that is not security's to restructure.
 *
 * So the shared part is expressed the way this package already expresses every cross-cutting
 * capability — `JudgesSchemaObjects`, `JudgesMigrationStatements`, `DeclaresJudgedObjectTypes`,
 * `DerivesDowntimeClass` are all contracts for exactly this reason. The commonality here is three
 * methods, and three methods do not justify rebuilding an inheritance tree.
 *
 * ## The two axes stay apart
 *
 * `severity()` is NOT the level. A rule's level says how strict a project has to be before the rule
 * is asked at all; its severity says how bad the answer is when it fires. A security rule is
 * deliberately reachable at level 0 and still gated by `security.min_severity` — the two axes cross
 * rather than nest, and a rule that folded one into the other would make the security suite
 * unreachable for the projects that most need it.
 */
interface DeclaresSecurityPosture
{
    /**
     * How bad it is when this rule fires — the security axis, never the level.
     *
     * Nullable, and NOT because null is acceptable here. It is the signature every rule already
     * inherits from `RuleMetadataDefaults`, where null is the correct answer for the safety rules
     * that are gated by level instead. PHP will not let a subclass re-declare an inherited concrete
     * method as abstract, and narrowing the type on the interface makes the inherited one
     * incompatible — so the type system cannot state "a security rule has a real severity" at all.
     *
     * It is therefore stated where it CAN be enforced: an arch test walks every implementation of
     * this contract and fails on a null. Written down here because a nullable type beside a rule
     * that must never be null reads like an oversight, and the next person to see it should know it
     * was measured rather than missed.
     */
    public function severity(): ?Severity;

    /**
     * What this rule does NOT see.
     *
     * The honesty slot, and it earns its place by being answerable rather than aspirational: a
     * security rule that reports a clean result over a surface it never examined is the one failure
     * this package cannot tolerate, because the reassuring answer and the correct one look identical
     * from outside. A rule naming its own blind spots turns "found nothing" into "found nothing HERE",
     * which is a different sentence.
     *
     * Empty is a legitimate answer and means "nothing this rule claims to cover escapes it" — not
     * "nobody has thought about it yet". Filling these in per rule is its own piece of work, because
     * a blind spot invented to look thorough is worse than an honest empty list.
     *
     * @return list<string>
     */
    public function limitations(): array;
}
