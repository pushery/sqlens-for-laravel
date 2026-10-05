<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\ShippedLocale;

/**
 * The sentence a person reads for a skip: what its reason means for the object it names.
 *
 * The reason id and the reader's detail say which reason and where. Neither says what the reason
 * means or what to do about it, and that is what each `catalog.skip.*` sentence is written for:
 * a missing grant and a spent budget are fixed in unrelated places.
 *
 * Only the sentence is translated. The reason id stays English on the skip, because it reaches the
 * JSON envelope, where a translated identifier would be a breaking change per language.
 */
final readonly class SkipSentence
{
    public function __construct(private Translator $translator) {}

    /**
     * The sentence for this skip, naming its object.
     *
     * The driver and the error code fill the two sentences that name them, `unsupported_driver` and
     * `unexpected_error`; every other sentence ignores them.
     */
    public function for(CatalogSkip $skip, string $driver): string
    {
        return (string) $this->translator->get('sqlens::messages.'.$skip->reason->translationKey(), [
            'reference' => $skip->reference,
            'driver' => $driver,
            'code' => (string) $skip->errorCode,
        ], ShippedLocale::CODE);
    }
}
