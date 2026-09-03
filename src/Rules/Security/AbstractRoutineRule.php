<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The shape both "this routine runs as somebody else" rules have.
 *
 * Two of them, and they split on ONE flag: whether the routine pins its own `search_path`. Everything
 * before that split is identical, and identical logic written twice is logic that stops being
 * identical the first time one copy is fixed.
 *
 * What the base owns:
 *
 * - **A routine that came back half-read.** A verdict about a field nobody could read is the silent
 *   green in miniature, so it is `undetermined` with the reason instead.
 * - **A routine that runs as its CALLER.** `SECURITY INVOKER` is the default and the safe case; it is
 *   simply not what either rule is about, and neither may speak about it.
 * - **An engine with no stored routines.** MySQL has them, so unlike the HBA family this is not an
 *   engine question — but a reading that returned none produces no subjects, and both rules are then
 *   silent by construction. That silence is correct: a schema with no routines has no routine
 *   problem, which is a different sentence from "nobody could look".
 */
abstract class AbstractRoutineRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Routines only. The routine reading is refusable on a managed database, so "no routine subject"
     * is an ordinary state here and must not be reported as a family that ran and found nothing.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Routine];
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /**
     * Whether this rule is the one for a routine that pins its `search_path`.
     *
     * The single axis the two rules differ on, expressed as a question rather than as duplicated
     * conditions — so the pair cannot drift into both answering, or neither.
     */
    abstract protected function appliesToPinnedPath(): bool;

    /** What this rule says about a definer routine it is the one for. */
    abstract protected function message(SchemaObject $object): string;

    /**
     * A last condition, for a rule that shares the pinned/unpinned half with another.
     *
     * Two rules now sit on the PINNED side: one reports every definer routine as inventory, the
     * other speaks only where the pinned path is measurably open. Without this hook the second would
     * have to repeat the base's filtering to add one condition, and repeated filtering is how a pair
     * of rules ends up disagreeing about which subjects they cover.
     *
     * Defaults to true, so a rule that is the only one for its half says nothing extra.
     */
    protected function appliesToSubject(SchemaObject $object): bool
    {
        return true;
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Routine) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('%s could not be read in full, so whose privileges it runs with is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        // `SECURITY INVOKER` — the default, and the case neither rule is about. A routine that runs as
        // whoever called it grants nothing that the caller did not already hold.
        if ($object->getBool('definer') !== true) {
            return [];
        }

        // An engine without a per-routine search path cannot have the escalation, and cannot have the
        // "pinned" state either — so it is the inventory rule that speaks there, and only it.
        $pinned = $object->getBool('search_path_configurable') !== true
            || $object->getBool('pins_search_path') === true;

        if ($pinned !== $this->appliesToPinnedPath()) {
            return [];
        }

        if (! $this->appliesToSubject($object)) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }
}
