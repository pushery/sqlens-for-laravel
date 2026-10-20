<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use Laravel\Mcp\Request;
use Laravel\Mcp\Server\Tool;
use Override;

/**
 * Every SQLens MCP tool, and the two things the SDK does not give one.
 *
 * ## 1. It declares whether it ships off
 *
 * `mutating()` is abstract, so a tool cannot be written without answering. The answer is stated
 * twice on purpose: here, by the tool that knows, and in `ConfigSchema::MCP_MUTATING_TOOLS`, which
 * the policy and the configuration read, because which tools are dangerous must not depend on
 * loading the tool classes. `ToolRegistryTest` holds the two together. A flag that could be
 * inferred — from a name, from a base class — would be a guess about the one property that decides
 * whether an agent can reach a database a project did not hand it.
 *
 * What a tool does to its world reaches the client separately, as the MCP annotations each tool
 * class carries: read-only for every tool that writes nothing, destructive for the one that
 * creates and drops databases. Mutating is about reach as well as writes, so the two differ for
 * `predeploy`, which writes nothing and reads the production database.
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
 * finding means. The package speaks one language everywhere (`ShippedLocale`), and this surface
 * would stay English even if it spoke more: translating protocol metadata would make one server
 * answer differently depending on a setting the client cannot see. Deliberate, and written down
 * here so nobody later "fixes" it.
 */
abstract class SqlensTool extends Tool
{
    /**
     * Whether this tool ships off and is enabled by name: it changes something, a database, a file or a
     * deployment, or it reaches a database a project decides on by name.
     *
     * Nothing infers this: it is stated by the tool that knows, and `ConfigSchema::MCP_MUTATING_TOOLS`
     * states the same set for the policy and the configuration.
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
     * validates its own input, and a tool that could be written without doing so would be one hole
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
     * The arguments, validated against {@see self::rules()}, an integer and a boolean in their own types.
     *
     * `final` on purpose: a tool that overrode this could quietly accept what the rules refuse, and
     * the guard reading those rules would certify something that never ran.
     *
     * The rules let a numeric string through `integer` and `1` or `"0"` through `boolean`, and every
     * tool reads such a value with `is_int()` or `=== true`. Handed on as it arrived, a level sent as
     * `"5"` was valid and then treated as never sent. Converted here, once, a value the rules accepted
     * is the value the tool reads.
     *
     * @return array<string, mixed>
     */
    final protected function validated(Request $request): array
    {
        $rules = $this->rules();
        $validated = $request->validate($rules);

        foreach ($rules as $parameter => $parameterRules) {
            if (! array_key_exists($parameter, $validated)) {
                continue;
            }

            if (in_array('integer', $parameterRules, true)) {
                $integer = filter_var($validated[$parameter], FILTER_VALIDATE_INT);
                $validated[$parameter] = $integer === false ? $validated[$parameter] : $integer;
            } elseif (in_array('boolean', $parameterRules, true)) {
                $validated[$parameter] = filter_var($validated[$parameter], FILTER_VALIDATE_BOOLEAN);
            }
        }

        return $validated;
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
     * Projected: `in:` as an enum, `min:` and `max:` as bounds, a plain `regex:` as a pattern and
     * `date_format:Y-m-d` as the date format. `not_regex:` stays a rule only, because a pattern
     * cannot say what a value must not contain.
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

                $pattern = str_starts_with($rule, 'regex:') ? $this->schemaPattern(substr($rule, 6)) : null;

                if ($pattern !== null && ($properties[$parameter]['type'] ?? null) === 'string') {
                    $properties[$parameter]['pattern'] = $pattern;
                }

                if ($rule === 'date_format:Y-m-d' && ($properties[$parameter]['type'] ?? null) === 'string') {
                    $properties[$parameter]['format'] = 'date';
                }
            }
        }

        return $properties;
    }

    /**
     * A validation regex as a JSON Schema `pattern`, or null where it cannot be one.
     *
     * Only the plain form is carried: an expression between slashes with no modifier, built from the
     * anchors, character classes and alternatives the tools use, which the ECMAScript dialect of JSON
     * Schema reads the same way. A modifier would change the meaning of the body, so such a rule stays a
     * rule only.
     */
    private function schemaPattern(string $regex): ?string
    {
        return preg_match('#^/(.+)/$#s', $regex, $body) === 1 ? $body[1] : null;
    }
}
