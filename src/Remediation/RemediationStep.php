<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

/**
 * One step of a safe sequence — material an agent applies, never something the tool executes.
 *
 * ## Why the text is a KEY and not a sentence
 *
 * `noteKey` names a translated string; it is not the string. A schema that carried prose would make
 * every payload a translation unit, and the same fix would arrive in seven wordings that drift apart
 * — while the STRUCTURE, which is what a machine acts on, is the same everywhere. The note is for
 * the person reading over the agent's shoulder; the structure is for the agent.
 *
 * ## Why the placeholders are named and filled deterministically
 *
 * `sqlTemplate` carries `{{table}}`, `{{column}}`, `{{index}}` — names filled from the finding's own
 * context and from nothing else. No free SQL generation, no heuristic, no model. A template that
 * could be completed by guessing would be a fix nobody could review, and reviewing it is the whole
 * point of handing it over instead of applying it.
 */
final readonly class RemediationStep
{
    /**
     * @param  int  $order  1-based; the sequence is the safety property, so it is stated rather than
     *                      inferred from array position, which a merge or a filter would silently
     *                      renumber
     * @param  string|null  $sqlTemplate  with named placeholders, or null for a step that is not SQL
     * @param  string|null  $laravelSnippet  the framework-shaped equivalent, where one exists
     * @param  bool  $withinTransaction  whether this step may run inside the migration's transaction
     *                                   — false is the load-bearing value: `CONCURRENTLY` and its
     *                                   relatives fail inside one, and a reader who assumes the
     *                                   default gets a sequence that cannot run
     * @param  string  $noteKey  translation key for the human-readable note
     */
    public function __construct(
        public int $order,
        public RemediationStepKind $kind,
        public string $noteKey,
        public ?string $sqlTemplate = null,
        public ?string $laravelSnippet = null,
        public bool $withinTransaction = true,
    ) {}

    /**
     * A deterministic projection with a fixed key order; absent optional fields are omitted rather
     * than serialized as null, so a consumer branches on presence rather than on emptiness.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter([
            'order' => $this->order,
            'kind' => $this->kind->value,
            'note_key' => $this->noteKey,
            'sql_template' => $this->sqlTemplate,
            'laravel_snippet' => $this->laravelSnippet,
            'within_transaction' => $this->withinTransaction,
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * The step with its placeholders filled from a finding's own context.
     *
     * Only the names this class declares, and only from values the caller measured. An unknown
     * placeholder is left standing rather than blanked: a template that quietly lost a table name
     * would read as a complete statement about the wrong object, which is worse than one that
     * visibly still has a hole in it.
     *
     * @param  array<string, string>  $context  placeholder name => value, without the braces
     */
    public function filled(array $context): self
    {
        $replace = static function (?string $template) use ($context): ?string {
            if ($template === null) {
                return null;
            }

            foreach ($context as $name => $value) {
                $template = str_replace('{{'.$name.'}}', $value, $template);
            }

            return $template;
        };

        return new self(
            $this->order,
            $this->kind,
            $this->noteKey,
            $replace($this->sqlTemplate),
            $replace($this->laravelSnippet),
            $this->withinTransaction,
        );
    }
}
