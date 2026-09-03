<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

use Illuminate\Contracts\Config\Repository as Config;
use JsonException;

/**
 * Reads the end-of-life data, from the first of three files that answers.
 *
 * ## The order, and why it is fixed
 *
 * 1. `sqlens.security.advisories.path` — an explicit choice by the project, so it beats everything.
 * 2. the application's published copy under its own `resources/data/eol.json`.
 * 3. the copy bundled with this package, which always exists and is therefore the floor.
 *
 * A refresh writes to (1) or (2). If the order were "whichever is found first" in some directory
 * walk, a refresh could land in a file nobody reads and the run would keep reporting the old
 * verdict — silently, because both files are perfectly valid. So the order is fixed, and the file
 * that actually answered travels out with the data.
 *
 * ## Never the network, and never an exception
 *
 * This reads local files only. That is the whole design: a patch-currency check that had to reach
 * the network would be unusable on a CI runner without egress and would answer the same question
 * differently on two days.
 *
 * And it never throws. Every failure — missing, unreadable, malformed, a schema version this build
 * does not understand — comes back as an {@see EolLookup} carrying a sentence. A security run has
 * plenty else to report, and taking the whole run down over one absent artifact would lose all of
 * it. The caller turns the sentence into an `undetermined` finding, which is the honest shape:
 * nothing was compared, so nothing is known, and "nothing is known" is not "up to date".
 */
final class EolRepository
{
    public const string BUNDLED_FILE = 'resources/data/eol.json';

    /** The schema this build understands. A file from the future is refused rather than guessed at. */
    public const int SCHEMA_VERSION = 1;

    private ?EolLookup $cached = null;

    public function __construct(
        private readonly ?Config $config,
        /** The application's base path; the published copy is looked for beneath it. */
        private readonly string $basePath,
        /**
         * One file, taking the place of the whole resolution order.
         *
         * Null for every ordinary reader. Set only by {@see forFile()}, where the caller already
         * knows exactly which file it means and asking the order to find it would let it find a
         * different one.
         */
        private readonly ?string $only = null,
    ) {}

    /**
     * A reading of bytes that are already in hand, with no filesystem involved at all.
     *
     * The refresh validates a fetched response by READING it with this — the same parser the rules
     * judge from, so a refresh can never accept a document the run would then reject.
     *
     * The first version staged the bytes in a temporary file and read that. It worked, and the
     * security preset was right to refuse it: a temp file is a second place the response exists,
     * with its own lifetime and its own permissions, for no reason other than that the reader
     * happened to take a path. The parser never needed one.
     *
     * @param  string  $label  what the response is called in a failure sentence — a reader who gets
     *                         "could not be read" needs to know it was the FETCH and not their file
     */
    public static function forDocument(string $body, string $label): EolLookup
    {
        return new self(null, '')->parseDocument($body, $label);
    }

    /**
     * A reader over exactly one file, and no resolution order at all.
     *
     * The refresh uses it to validate fetched bytes by READING them with the same parser the rules
     * judge from — a second validator would eventually disagree with the reader about what a valid
     * file is, and the disagreement would surface as a refresh that succeeds and a run that then
     * calls the data unreadable.
     *
     * A named constructor rather than a stand-in configuration object: the first attempt built a
     * one-key implementation of Laravel's config contract, which is a class pretending to be general
     * so that one caller can be specific. This says what it means.
     */
    public static function forFile(string $path): self
    {
        return new self(null, '', $path);
    }

    /**
     * A reader over the bundled file alone — what an unconfigured project gets.
     *
     * Not a stub. It answers with the same file, through the same parser, as a configured project
     * that happens to have configured nothing; the only thing it cannot do is honor
     * `sqlens.security.advisories.path`, because it was handed no configuration to read it from.
     * The container builds the configured one and passes it down; this is the default for the call
     * sites that have no container.
     */
    public static function bundled(): self
    {
        // No configuration at all rather than an empty one: the concrete config repository lives in
        // a component this package does not depend on, and pulling illuminate/config in so a default
        // constructor could build an empty object would be a shipped dependency bought for a stub.
        // Null reads as "nothing configured", which is precisely what this constructor means.
        return new self(null, '');
    }

    /**
     * The data, or a named reason there is none.
     *
     * Cached per instance rather than statically: a static cache would outlive a test that changes
     * the configured path, and the next test would silently read the previous one's file.
     */
    public function lookup(): EolLookup
    {
        return $this->cached ??= $this->resolve();
    }

    private function resolve(): EolLookup
    {
        if ($this->only !== null) {
            return $this->read($this->only, EolSource::Configured);
        }

        $configured = $this->config?->get('sqlens.security.advisories.path');

        // A CONFIGURED path that does not answer is a hard stop, not a reason to fall through. The
        // project named a file; reading a different one instead would be the exact silent
        // substitution this class exists to prevent — and the operator would see verdicts from a
        // file they had deliberately replaced.
        if (is_string($configured) && $configured !== '') {
            return $this->read($configured, EolSource::Configured);
        }

        $published = $this->basePath.'/'.self::BUNDLED_FILE;

        if (is_file($published)) {
            return $this->read($published, EolSource::Published);
        }

        return $this->read(dirname(__DIR__, 3).'/'.self::BUNDLED_FILE, EolSource::Bundled);
    }

    /** Shared by the file path and the in-hand path, so both refuse exactly the same documents. */
    private function parseDocument(string $raw, string $path, EolSource $source = EolSource::Configured): EolLookup
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            return EolLookup::unavailable(sprintf('the %s advisory file "%s" is not valid JSON: %s', $source->value, $path, $exception->getMessage()));
        }

        return $this->parse($decoded, $path, $source);
    }

    private function read(string $path, EolSource $source): EolLookup
    {
        $raw = @file_get_contents($path);

        // ONE branch for "no bytes came back", covering both a path that names nothing and a file
        // that exists and would not open. Split in two it read better — a typo and a permission are
        // different problems — but the second half could not be proven: staging an unreadable file
        // needs a process that is not root, and the gate's container is. A branch no test can reach
        // is a branch nobody has checked, and this package does not get to keep those just because
        // they are sympathetic.
        //
        // Nothing actionable is lost. The message names both causes, and "check that it exists and
        // is readable" is one instruction either way.
        if ($raw === false) {
            return EolLookup::unavailable(sprintf(
                'the %s advisory file "%s" could not be read — it does not exist, or it exists and would not open',
                $source->value,
                $path,
            ));
        }

        return $this->parseDocument($raw, $path, $source);
    }

    /** @param  array<string, mixed>  $data */
    private function parse(array $data, string $path, EolSource $source): EolLookup
    {
        $version = $data['schema_version'] ?? null;

        // Refused rather than read leniently. A newer schema may have moved a field this build
        // still reads, and reading it anyway would produce confident verdicts from a shape nobody
        // measured — worse than no verdict, because it looks like one.
        if ($version !== self::SCHEMA_VERSION) {
            return EolLookup::unavailable(sprintf(
                'the %s advisory file "%s" declares schema_version %s; this build understands %d',
                $source->value,
                $path,
                is_scalar($version) ? json_encode($version) : 'nothing usable',
                self::SCHEMA_VERSION,
            ));
        }

        $products = $data['products'] ?? null;

        if (! is_array($products) || $products === []) {
            return EolLookup::unavailable(sprintf('the %s advisory file "%s" carries no products', $source->value, $path));
        }

        $cycles = [];

        foreach ($products as $product => $entry) {
            if (! is_string($product) || ! is_array($entry) || ! is_array($entry['cycles'] ?? null)) {
                return EolLookup::unavailable(sprintf('the %s advisory file "%s" has a product without a cycles list', $source->value, $path));
            }

            $parsed = $this->cycles($entry['cycles']);

            if ($parsed === null) {
                return EolLookup::unavailable(sprintf('the %s advisory file "%s" has a malformed cycle under "%s"', $source->value, $path, $product));
            }

            $cycles[$product] = $parsed;
        }

        $compiledOn = $data['compiled_on'] ?? null;

        if (! is_string($compiledOn) || $compiledOn === '') {
            return EolLookup::unavailable(sprintf('the %s advisory file "%s" does not say when it was compiled', $source->value, $path));
        }

        return EolLookup::found(new EolData($cycles, $path, $source, $compiledOn));
    }

    /**
     * @param  array<int|string, mixed>  $raw
     * @return list<EolCycle>|null null when any entry is malformed — a partially read file would
     *                             answer some versions and silently not others
     */
    private function cycles(array $raw): ?array
    {
        $cycles = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
                return null;
            }

            $cycle = $entry['cycle'] ?? null;
            $release = $entry['release_date'] ?? null;
            $eol = $entry['eol_date'] ?? null;
            $note = $entry['note'] ?? null;

            if (! is_string($cycle) || ! is_string($release) || ! is_string($eol) || ! is_string($note)) {
                return null;
            }

            if (! $this->isIsoDate($release) || ! $this->isIsoDate($eol)) {
                return null;
            }

            $latest = $entry['latest_patch'] ?? null;

            // Present-but-not-a-string is malformed; ABSENT is not. A file that records no patch
            // levels is the bundled shape, and refusing it would refuse the artifact this package
            // ships.
            if ($latest !== null && ! is_string($latest)) {
                return null;
            }

            $cycles[] = new EolCycle($cycle, $latest, $release, $eol, ($entry['lts'] ?? null) === true, $note);
        }

        return $cycles;
    }

    /**
     * Whether a date is ISO-8601 `YYYY-MM-DD`, and a real day.
     *
     * The format check alone would accept `2026-02-31`, which sorts perfectly and does not exist —
     * and every comparison in {@see EolCycle} is a string comparison that would happily use it.
     */
    private function isIsoDate(string $value): bool
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) !== 1) {
            return false;
        }

        [$year, $month, $day] = array_map(intval(...), explode('-', $value));

        return checkdate($month, $day, $year);
    }
}
