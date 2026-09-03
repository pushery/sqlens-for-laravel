<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use Laravel\Mcp\Request;
use Laravel\Mcp\Server\Tool;
use Override;

/**
 * Every SQLens MCP tool, and the two things the SDK does not give one.
 *
 * ## 1. It declares whether it changes anything
 *
 * `mutating()` is abstract, so a tool cannot be written without answering. The registry reads it to
 * decide what ships on; the configuration reads the same answer to decide what a project may turn
 * on. A flag that could be inferred — from a name, from a base class — would be a guess about the
 * one property that decides whether an agent can alter a database.
 *
 * ## 2. Its published schema is CLOSED
 *
 * The SDK publishes `{"properties": …, "type": "object", "required": […]}` and no
 * `additionalProperties`, which in JSON Schema means "anything else is allowed too". Worse, it does
 * not enforce the schema at all: `CallTool` looks the tool up by name and calls it, and every
 * argument a client sent — declared or not, typed or not — is in the request.
 *
 * So the schema is closed here, in one place, for every tool at once. It is documentation rather
 * than a gate as long as the SDK does not check it, and that is exactly why each tool still
 * validates its own input: a closed schema tells an honest client what to send, and validation is
 * what handles a dishonest one.
 *
 * ## Why the names and descriptions stay English
 *
 * They are MACHINE surface — an agent reads them to choose a tool, not a person deciding what a
 * finding means. The seven-locale rule covers human-readable reporter and error text; protocol
 * metadata is not that, and translating it would make one server answer differently depending on a
 * setting the client cannot see. Deliberate, and written down here so nobody later "fixes" it.
 */
abstract class SqlensTool extends Tool
{
    /**
     * Whether calling this tool can change anything — a database, a file, a deployment.
     *
     * The registry ships a mutating tool OFF and requires it to be enabled by name. Nothing infers
     * this: it is stated by the tool that knows.
     */
    abstract public function mutating(): bool;

    /**
     * The validation rules for every parameter this tool accepts, as Laravel rules.
     *
     * ## Why this is abstract rather than a call inside `handle()`
     *
     * Two reasons, and the second is the one that makes it structural.
     *
     * The SDK publishes an `inputSchema` and does not check a single argument against it — measured:
     * a missing required field and a wrongly typed one both arrive at the tool. So every tool
     * validates its own input, and a tool that could be written WITHOUT doing so would be one hole
     * away from a surface whose whole risk profile is what it accepts.
     *
     * And rules declared here are READABLE. A guard can walk every registered tool and hold each
     * parameter to a shape the package allows — an enum, a bounded integer, a name from a
     * configured set, a path with a pattern. Rules buried in a method body can be read by nobody,
     * so the promise "no tool ever takes free-text SQL" would be a sentence in a docblock rather
     * than a fence.
     *
     * @return array<string, list<string>>
     */
    abstract public function rules(): array;

    /**
     * The arguments, validated against {@see self::rules()}.
     *
     * `final` on purpose: a tool that overrode this could quietly accept what the rules refuse, and
     * the guard reading those rules would certify something that never ran.
     *
     * @return array<string, mixed>
     */
    final protected function validated(Request $request): array
    {
        return $request->validate($this->rules());
    }

    /**
     * The tool as the protocol publishes it, with a CLOSED input schema.
     *
     * @return array{
     *     name: string,
     *     title?: string|null,
     *     description?: string|null,
     *     inputSchema?: array<string, mixed>,
     *     outputSchema?: array<string, mixed>,
     *     annotations?: array<string, mixed>|object,
     *     _meta?: array<string, mixed>
     * }
     */
    #[Override]
    public function toArray(): array
    {
        $published = parent::toArray();

        if (is_array($published['inputSchema'] ?? null)) {
            // An open schema says "and anything else you like". On a surface whose whole risk
            // profile is what it accepts, that is the wrong default to inherit silently.
            $published['inputSchema']['additionalProperties'] = false;
            $properties = $published['inputSchema']['properties'] ?? null;
            $keyed = [];

            if (is_array($properties)) {
                foreach ($properties as $name => $property) {
                    $keyed[(string) $name] = $property;
                }
            }

            $published['inputSchema']['properties'] = $this->constrained($keyed);
        }

        return $published;
    }

    /**
     * The published properties, carrying the bounds the rules already enforce.
     *
     * The SDK's schema builder describes a type and a sentence; the rules describe a RANGE. Without
     * this the published contract says `{"type": "string"}` for a parameter that in fact accepts one
     * of six words — so an honest client cannot tell what to send, and the schema promises more
     * freedom than the tool allows. One source, projected into both places.
     *
     * @param  array<string, mixed>  $properties
     * @return array<string, mixed>
     */
    private function constrained(array $properties): array
    {
        foreach ($this->rules() as $parameter => $rules) {
            if (! is_array($properties[$parameter] ?? null)) {
                continue;
            }

            foreach ($rules as $rule) {
                if (str_starts_with($rule, 'in:')) {
                    $properties[$parameter]['enum'] = explode(',', substr($rule, 3));
                }

                if (str_starts_with($rule, 'max:') && ($properties[$parameter]['type'] ?? null) === 'string') {
                    $properties[$parameter]['maxLength'] = (int) substr($rule, 4);
                }

                if (str_starts_with($rule, 'max:') && ($properties[$parameter]['type'] ?? null) === 'integer') {
                    $properties[$parameter]['maximum'] = (int) substr($rule, 4);
                }

                if (str_starts_with($rule, 'min:') && ($properties[$parameter]['type'] ?? null) === 'integer') {
                    $properties[$parameter]['minimum'] = (int) substr($rule, 4);
                }
            }
        }

        return $properties;
    }
}
