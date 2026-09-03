<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Contracts\Subject;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * A settings reading, as subjects the existing rule engine already knows how to dispatch.
 *
 * ## Why a server variable is a schema object and not a new subject kind
 *
 * The first sketch gave server settings their own {@see Subject}
 * implementation and their own dispatch in the audit runner. It would have worked, and it would
 * have been a second path through the engine for a question the first path already answers: rules
 * that judge one named thing read from a live server. `SchemaObjectType::Setting` was in the enum
 * before this class existed, which is the shape of the answer — a variable is a catalog object with
 * a name and attributes, exactly like a table or an index.
 *
 * Keeping it on the one path means the level gate, the category filter, suppression, the baseline,
 * the reporters and the deduplication all treat a setting finding like every other catalog finding,
 * with no per-kind branch anywhere. A second subject kind would have needed each of those to learn
 * about it, and each would have been a place to forget.
 *
 * ## The attribute names are the contract
 *
 * A rule reads `server_value` and never `value` — see {@see Setting::$serverValue} for why that
 * distinction is load-bearing rather than cosmetic. Both are attached, because a rule that reports a
 * deviation is more useful when it can also say what the audit's own connection is running with.
 */
final readonly class SettingSubjects
{
    /**
     * Every readable setting in the reading, as a subject.
     *
     * A setting the server withheld is still emitted, with a null `server_value`, rather than
     * dropped. Dropping it would leave a rule with no subject at all, and "no subject" is
     * indistinguishable from "no problem" — the silent green this package is built to refuse. Emitted
     * with a null value, the rule reports `undetermined` with a reason, which is the honest answer.
     *
     * @return list<SchemaObject>
     */
    public static function fromReading(
        SettingsReading $reading,
        SubjectContext $context,
        SettingCrossFacts $facts = new SettingCrossFacts,
        ?PoolerReading $pooler = null,
    ): array {
        // No default that claims anything. A caller that did not establish the topology has not
        // established it, and the honest stamp is "undetermined" — which the rules then report
        // rather than judging a value they cannot vouch for the provenance of.
        $pooler ??= PoolerReading::undetermined(['the topology was not established']);

        $subjects = [];

        foreach ($reading->settings as $setting) {
            $subjects[] = new SchemaObject(
                SchemaObjectType::Setting,
                $setting->name,
                null,
                [
                    // What the SERVER is configured to — the only field a server-baseline rule judges.
                    'server_value' => $setting->serverValue(),
                    // What the reading session is running with. Not judged; reported, so a finding can
                    // say "the server says X, this connection is running with Y" instead of leaving a
                    // reader to wonder which one their application sees.
                    'session_value' => $setting->value,
                    'source' => $setting->source,
                    'source_file' => $setting->sourceFile,
                    'unit' => $setting->unit,
                    'change_context' => $setting->context,
                    'pending_restart' => $setting->pendingRestart,
                    'overridden_in_session' => $setting->overriddenInThisSession(),
                    // Whatever the driver measured BESIDE this variable, flattened by
                    // SettingCrossFacts so no rule reads a raw key. Only this variable's facts —
                    // a reading carries hundreds of settings and a flat map would hang every
                    // fact on every one of them.
                    ...$facts->attributesFor($setting->name),
                    // The topology the reading came through, stamped onto every setting subject
                    // rather than checked once in the runner. A server-baseline rule's whole
                    // premise is that the value it judges came from the instance it names, and
                    // that premise belongs where the judgment is made.
                    'pooler' => $pooler->verdict->value,
                    'pooler_signals' => $pooler->describe(),
                ],
                $context,
            );
        }

        // Sorted by name so a run over the same server produces the same order. The readers iterate
        // whatever order the catalog view returned, and neither engine promises one.
        usort($subjects, static fn (SchemaObject $a, SchemaObject $b): int => strcmp($a->qualifiedName, $b->qualifiedName));

        return $subjects;
    }
}
