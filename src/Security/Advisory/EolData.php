<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * The end-of-life file, parsed — plus the path it was parsed from.
 *
 * The origin travels with the data rather than being remembered by the caller, because a run that
 * judged a server out of support has to be able to say which file it judged from. Three files can
 * answer, and an operator who refreshed one of them and still sees the old verdict is looking for
 * exactly this string.
 */
final readonly class EolData
{
    /** @param  array<string, list<EolCycle>>  $cycles  keyed by product: `postgresql`, `mysql` */
    public function __construct(
        public array $cycles,
        public string $path,
        public EolSource $source,
        /** The day the file's compiler last checked the vendors, so a reader can judge its age. */
        public string $compiledOn,
    ) {}

    /**
     * The cycle a server version belongs to, or null when the file does not know it.
     *
     * Null is a real answer and not an error: a brand-new major that no released version of this
     * package has heard of is exactly the case where the honest report is "not known here" rather
     * than a guess in either direction. The caller turns it into an undetermined with a reason.
     */
    public function cycleFor(string $product, string $version): ?EolCycle
    {
        foreach ($this->cycles[$product] ?? [] as $cycle) {
            if ($cycle->cycle === $version) {
                return $cycle;
            }
        }

        return null;
    }

    /**
     * Every product this file carries, sorted, so a caller can enumerate deterministically.
     *
     * @return list<string>
     */
    public function products(): array
    {
        $products = array_keys($this->cycles);
        sort($products);

        return $products;
    }
}
