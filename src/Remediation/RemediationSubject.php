<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Agent\Remediation\RemediationValidator;

/**
 * What a fix template is ABOUT — the statement somebody wrote, or an object the run found.
 *
 * ## Why a discriminator rather than a second payload type
 *
 * `RemediationPayload` was written for a lint finding: it rewrites a statement that exists. A
 * catalog finding is the other shape — it names a state a database is IN, and the fix is a
 * migration nobody has written yet. Several fields mean something different there, and one means
 * nothing at all.
 *
 * Three ways to say that were on the table. A second payload type is honest and costs a second
 * published schema, a second version line and a second thing for a consumer to learn. Reusing the
 * payload silently is cheapest and produces the reader this package exists to protect: somebody who
 * sees `downtime_class: online` on a state finding and takes it as a statement about their next
 * deploy.
 *
 * The discriminator is the third, and it is the only one where the answer is IN the document. A
 * consumer reads one field and knows which of the two shapes it holds, instead of inferring it from
 * which rule produced the finding.
 *
 * ## It cost a schema version, and the argument that said otherwise is kept here because it was good
 *
 * This block used to read: the schema says *"within a version, unknown keys may be ignored"*, adding
 * `subject` adds a key and reinterprets none, `statement` is the default, so a version-1 reader
 * reads what it read before. Every clause of that is true, and the conclusion was still wrong.
 *
 * It is an argument about a READER. The thing that breaks is a VALIDATOR. The version-1 document
 * carries `additionalProperties: false`, so the copy a consumer vendored from v0.3.0 refuses a
 * payload carrying this field — the tolerance the quoted sentence promises is one the document
 * never granted. And `subject` went into `required`, so the refusal runs the other way too.
 *
 * So the payload is version 2, version 1 is frozen at the bytes three tags published, and the
 * quoted sentence is gone from both documents. `PublishedSchemaTest` now holds every published
 * version's field set by digest, which is the check that would have caught this without anyone
 * having to reason about it.
 *
 * ## The discriminator alone is not enough, and that is the other half
 *
 * A field that is merely *meaningless* for half the ground set is still a field somebody reads. So
 * {@see RemediationValidator} REFUSES a payload that sets one
 * where it does not apply, rather than rendering it and hoping. Absent is a fact; present and
 * ignored is a lie a reader cannot see.
 */
enum RemediationSubject: string
{
    /**
     * The template rewrites a statement the reader wrote.
     *
     * Placeholders come from the CANONICALIZED statement, `downtime_class` describes what applying
     * this deploy does, and `MigrationStatement` means "in this migration". Every payload this
     * package has ever produced is one of these, which is why it is the default.
     */
    case Statement = 'statement';

    /**
     * The template describes a migration that does not exist yet, for an object the run found.
     *
     * Placeholders come from the catalog object. There is no "this migration" and no deploy whose
     * effect a downtime class could describe — the effect arrives when somebody writes the
     * migration, and what it costs depends on what they write.
     */
    case SchemaObject = 'schema_object';

    /**
     * Whether a downtime class means anything for this subject.
     *
     * Its own method rather than a comparison at the call site: the question is asked by the
     * validator and by the schema documentation, and two spellings of one rule is how the two
     * stop agreeing.
     */
    public function carriesADowntimeClass(): bool
    {
        return $this === self::Statement;
    }
}
