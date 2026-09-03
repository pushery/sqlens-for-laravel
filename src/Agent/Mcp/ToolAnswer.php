<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Laravel\Mcp\Response;
use Pushery\SQLens\Exceptions\UnreasonedUndetermined;

/**
 * The one shape every SQLens MCP tool answers in — three-valued, with the reasons on the outside.
 *
 * ## The failure this exists to prevent
 *
 * In an agent loop the worst thing a tool can do is look green. "The run found nothing" and "the
 * run could not happen" produce the same empty list, and an agent reading the second as the first
 * reports the work as finished. So the two are never the same payload: `status` says which, and
 * `undetermined_reasons` says why — as a STRUCTURED field, because an agent reads fields and not
 * prose.
 *
 * ## Why the reasons list is always present
 *
 * Even when it is empty. A field that appeared only when something went wrong would make its
 * ABSENCE meaningful, and absence is exactly what a caller cannot distinguish from a client that
 * dropped it, a version that never had it, or a serializer that omits empties. Present and empty is
 * a statement; missing is a guess.
 *
 * ## Why an undetermined answer cannot be built without a reason
 *
 * The only way to produce one demands a non-empty reason and throws otherwise. A skip without a
 * reason is the package's own definition of a bug, and a rule enforced by a type cannot be
 * forgotten by the next tool somebody writes.
 */
final readonly class ToolAnswer
{
    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $reasons
     */
    private function __construct(
        public string $status,
        public array $payload,
        public array $reasons,
        public string $summary,
    ) {}

    /**
     * A tool that did its job.
     *
     * The summary is the tool's own sentence for a client that shows text rather than structure. It
     * must agree with the payload beside it: prose that said something else would be a second
     * reading of one answer, and the reader cannot tell which of the two to believe.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function of(array $payload, string $summary): self
    {
        return new self('ok', $payload, [], $summary);
    }

    /**
     * A tool that could NOT do its job, and says why.
     *
     * @param  array<string, mixed>  $payload  anything the caller can still act on — a path, a name
     * @param  string  $also  a sentence the tool would have said anyway, kept beside the reason.
     *                        A run can be undetermined AND have something else worth saying — that
     *                        its list was cut, for instance — and dropping the second sentence
     *                        because the first exists would lose it for every text client.
     *
     * @throws UnreasonedUndetermined
     */
    public static function undetermined(string $reason, array $payload = [], string $also = ''): self
    {
        if (trim($reason) === '') {
            throw new UnreasonedUndetermined;
        }

        return new self(
            'undetermined',
            $payload,
            [$reason],
            // Spelled out, in the words a reader needs. "Could not be checked" and "no problems
            // found" are the two sentences this whole class exists to keep apart, and a client
            // showing only text would otherwise have nothing to tell them apart by.
            trim('This could NOT be checked: '.$reason.' '.trim($also)),
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            // Always present, even empty — see the class docblock for why an absent field would be
            // a guess rather than a statement.
            'undetermined_reasons' => $this->reasons,
            'summary' => $this->summary,
            ...$this->payload,
        ];
    }

    /** The answer as the protocol carries it. */
    public function toResponse(): Response
    {
        return Response::json($this->toArray());
    }

    /**
     * The same answer, marked as an error result.
     *
     * The payload is the SAME structure rather than a bare sentence. `isError` tells a client that
     * the call did not produce what it asked for; the fields tell it what happened — and a refusal
     * that dropped the structure would leave an agent parsing prose for the one thing it needs,
     * which is the shape this class exists to guarantee.
     */
    public function toErrorResponse(): Response
    {
        return Response::error(json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
