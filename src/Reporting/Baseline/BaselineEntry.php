<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Severity\Severity;

/**
 * One recorded finding in a baseline. Its identity is the fingerprint plus an
 * ordinal: the fingerprint recognizes the finding across reformats, and the ordinal
 * tells apart several genuinely identical findings in one subject (same rule, same
 * canonical statement) — a case a fingerprint alone cannot distinguish. The ordinal
 * is assigned deterministically, in the run's stable finding order, so the same
 * state always produces the same entries.
 *
 * The rule id and a human-readable subject travel with the entry so a baseline file
 * stays legible; they are not part of the identity, which is the fingerprint+ordinal.
 */
final readonly class BaselineEntry
{
    /**
     * The serialized fields of an entry, in the ONE order they are written in.
     * The serializer reads the order from here, so the file layout and the value
     * object can never disagree about which fields exist.
     *
     * @var array<string, string>
     */
    public const array FIELDS = [
        'fingerprint' => 'the stable identity of the finding',
        'ordinal' => 'which of several identical findings in one subject',
        'rule_id' => 'the rule that produced it (legibility, not identity)',
        'subject' => 'where it was found (legibility, not identity)',
        'kind' => 'what it was about: a migration, a catalog object or a call site',
        'category' => 'which gate judged it — a security entry reads differently from a level one',
        'severity' => 'the risk it carried, or null outside the severity-gated categories',
    ];

    public function __construct(
        public FindingFingerprint $fingerprint,
        public int $ordinal,
        public string $ruleId,
        public string $subject,
        /**
         * What the accepted finding was about: a migration, a catalog object or a call site.
         *
         * The lint suite and the audit suite read the one baseline, and each can match only the
         * entries of its own kind of finding. A rule may answer in both, so the rule id alone
         * cannot say whose an entry is, and the fingerprint does not give back the location it was
         * built from. A run judges only the entries of its own kinds and leaves the rest to the
         * other suite.
         */
        public LocationKind $kind,
        /**
         * The category, and with it the axis this entry was accepted on.
         *
         * A baseline is a list of things somebody looked at and decided to live with, and living
         * with a level-2 idiom finding is a different decision from living with a critical security
         * finding. Without the category the file cannot tell the two apart, so a reviewer reading it
         * a year later cannot tell which accepted entries deserve a second look.
         */
        public Category $category = Category::Safety,
        /** The risk it carried, or null outside the severity-gated categories. */
        public ?Severity $severity = null,
    ) {}

    /**
     * Build entries from proto-records, giving findings that share a fingerprint an
     * incrementing ordinal (0, 1, 2, …) in the order they arrive — which is the
     * Result's deterministic order, so the assignment is reproducible.
     *
     * @param  list<array{fingerprint: FindingFingerprint, ruleId: string, subject: string, kind: LocationKind, category?: Category, severity?: Severity|null}>  $protos
     * @return list<self>
     */
    public static function assign(array $protos): array
    {
        $nextOrdinal = [];
        $entries = [];

        foreach ($protos as $proto) {
            $key = $proto['fingerprint']->value;
            $ordinal = $nextOrdinal[$key] ?? 0;
            $nextOrdinal[$key] = $ordinal + 1;

            $entries[] = new self(
                $proto['fingerprint'],
                $ordinal,
                $proto['ruleId'],
                $proto['subject'],
                $proto['kind'],
                $proto['category'] ?? Category::Safety,
                $proto['severity'] ?? null,
            );
        }

        return $entries;
    }

    /** The unique key of the entry: its fingerprint disambiguated by the ordinal. */
    public function key(): string
    {
        return $this->fingerprint->value.'#'.$this->ordinal;
    }

    /**
     * The three fields a reviewer reads to judge whether accepting the finding was right.
     *
     * @return array{rule: string, category: string, severity: string}
     */
    public function legible(): array
    {
        return [
            'rule' => $this->ruleId,
            'category' => $this->category->value,
            'severity' => $this->severity->value ?? 'none',
        ];
    }

    /**
     * Where this entry misdescribes the finding it matches, as the sentence the finding carries;
     * null when it describes it truly.
     *
     * The fingerprint decides WHICH finding an entry matches. The rule, category and severity are
     * what a reviewer reads, and `sqlens:baseline` copies all three from the finding, so an entry it
     * wrote agrees with the finding. One that does not was edited by hand, or outlived a release that
     * re-rated its rule. Either way it no longer says what it accepts, and an entry reading
     * `convention` over a critical security finding would silence the finding while the file told the
     * reviewer it was a naming nit.
     */
    public function contradictionOf(Finding $finding): ?string
    {
        $recorded = $this->legible();
        $actual = [
            'rule' => $finding->ruleId,
            'category' => $finding->category->value,
            'severity' => $finding->severity->value ?? 'none',
        ];
        $wrong = array_keys(array_diff_assoc($recorded, $actual));

        if ($wrong === []) {
            return null;
        }

        return sprintf(
            'A baseline entry matches this finding and records %s, so it does not suppress it: an acceptance has to name what it accepts. Run sqlens:baseline --update to rewrite the entry from this finding, and read the diff before committing it.',
            implode(', ', array_map(
                static fn (string $field): string => sprintf('%s %s where the finding has %s', $field, $recorded[$field], $actual[$field]),
                $wrong,
            )),
        );
    }

    /**
     * @return array{fingerprint: string, ordinal: int, rule_id: string, subject: string, kind: string, category: string, severity: string|null}
     */
    public function toArray(): array
    {
        return [
            'fingerprint' => $this->fingerprint->value,
            'ordinal' => $this->ordinal,
            'rule_id' => $this->ruleId,
            'subject' => $this->subject,
            'kind' => $this->kind->value,
            // Written even when null, unlike the JSON report's finding projection. A baseline is a
            // file people edit and diff, and a key that appears and disappears per entry makes a
            // diff noisier than the change it carries — the report is read by machines a line at a
            // time, this is read by a person top to bottom.
            'category' => $this->category->value,
            'severity' => $this->severity?->value,
        ];
    }
}
