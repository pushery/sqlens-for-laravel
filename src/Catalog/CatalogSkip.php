<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Exceptions\InvalidCatalogSkip;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One object the catalog read did NOT deliver, with the reason it did not.
 *
 * The type is the guardrail, not a convention: the constructor is private, and every way in
 * requires a reason. A skip without one cannot be built — so "the read quietly dropped something"
 * is not a state this model can represent, which is a stronger promise than any review can make.
 *
 * The same discipline runs one level deeper for {@see SkipReason::UnexpectedError}: it also
 * requires the SQLSTATE or driver error code. Without that requirement an unexpected failure would
 * drift into `not_readable`, where it reads as "this server does not have that object" — a label
 * that invites nobody to look. A real fault deserves a reason of its own and the code that
 * identifies it.
 */
final readonly class CatalogSkip
{
    private function __construct(
        /** What KIND of object was skipped — the axis a reader groups by. */
        public SchemaObjectType $type,
        /**
         * The object, named as precisely as the read got: a qualified name where one is known,
         * otherwise the relation or scope that could not be read.
         */
        public string $reference,
        public SkipReason $reason,
        /**
         * The SQLSTATE or driver error code, REQUIRED for an unexpected error and null otherwise.
         *
         * Null for the other reasons on purpose rather than an empty string: they are not failures
         * and inventing a code for them would put a fault marker on ordinary behavior.
         */
        public ?string $errorCode,
        /**
         * What the read was doing, in the reader's own words — the catalog relation, the object's
         * definition, the budget that ran out. Optional, because a reason plus a reference is
         * already actionable and a detail nobody has is better absent than fabricated.
         */
        public ?string $detail,
        /**
         * The extension that OWNS the skipped object, when the skip is a scope decision about one.
         *
         * Carried as a value rather than parsed back out of {@see $detail}, and that is the whole
         * point of the field: the reader knows the owner at the moment it decides to exclude, and
         * re-deriving it from a sentence would make the condensation below depend on prose nobody
         * treats as a contract.
         *
         * Null everywhere else, including for an exclusion that is not about an extension.
         */
        public ?string $owningExtension = null,
    ) {}

    /**
     * A skip for any reason EXCEPT an unexpected error.
     *
     * The exclusion is enforced rather than documented: passing `unexpected_error` here throws,
     * because that reason has a required field this entry point cannot supply.
     */
    public static function for(
        SchemaObjectType $type,
        string $reference,
        SkipReason $reason,
        ?string $detail = null,
        ?string $owningExtension = null,
    ): self {
        if ($reason === SkipReason::UnexpectedError) {
            throw new InvalidCatalogSkip(
                'An unexpected_error skip must carry its SQLSTATE or driver error code — build it with CatalogSkip::unexpectedError().',
            );
        }

        return new self($type, $reference, $reason, null, $detail, $owningExtension);
    }

    /**
     * A skip for a database error nothing anticipated, with the code that identifies it.
     *
     * An empty code is refused rather than stored: a fault marker with no fault to look up is the
     * same dead end as no marker at all, and it looks like diligence.
     */
    public static function unexpectedError(
        SchemaObjectType $type,
        string $reference,
        string $errorCode,
        ?string $detail = null,
    ): self {
        if (trim($errorCode) === '') {
            throw new InvalidCatalogSkip('An unexpected_error skip needs a non-empty SQLSTATE or driver error code.');
        }

        return new self($type, $reference, SkipReason::UnexpectedError, $errorCode, $detail);
    }

    /**
     * One entry standing for every object of one KIND that one extension owns.
     *
     * The skip list is where a reader looks to find out what could NOT be checked, and a thousand
     * PostGIS function names are not that information — they bury it. Measured on the smallest
     * extension in the fixture tree: `pg_trgm` alone contributed 31 of 35 entries, all routines,
     * all saying the same thing.
     *
     * Nothing is lost that a reader could act on. The extension is named, the kind is named, the
     * count is exact, and the reason is unchanged — which is strictly more than a list of names
     * gives, because the list makes the count something you have to work out yourself.
     *
     * @param  int  $count  how many objects of this kind the extension owns; never below two,
     *                      because a single object is clearer named than counted
     */
    public static function extensionScope(SchemaObjectType $type, string $extension, int $count, string $detail): self
    {
        return new self(
            $type,
            $extension,
            SkipReason::ExcludedByConfig,
            // No error code: an exclusion is a decision, and a fault marker on ordinary behavior is
            // the thing the constructor's own docblock refuses.
            null,
            // The extension is already the `reference`, and the producer's own sentence already
            // says who owns them — so this adds the count and the kind and nothing else. A summary
            // that repeats the clause it is summarizing reads like two facts and is one.
            sprintf('%d %s objects — %s', $count, $type->value, $detail),
            $extension,
        );
    }

    /**
     * The sort key that puts skips in a stable order — the same (type, reference) ordering the
     * snapshot's objects use, so a serialized snapshot is byte-identical across runs and machines.
     */
    public function sortKey(): string
    {
        return $this->type->value.':'.$this->reference;
    }

    /** @return array{type: string, reference: string, reason: string, error_code: string|null, detail: string|null} */
    public function toArray(): array
    {
        return [
            'type' => $this->type->value,
            'reference' => $this->reference,
            'reason' => $this->reason->value,
            'error_code' => $this->errorCode,
            'detail' => $this->detail,
        ];
    }
}
