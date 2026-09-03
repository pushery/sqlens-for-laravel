<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * The kind of a configuration violation. Machine-readable so a reporter can
 * group and translate violations without parsing message strings; the phrase
 * carries the kind-specific remedy, because the two hardest kinds are only
 * fixable when the message explains the mechanism that caused them.
 */
enum ConfigViolationKind: string
{
    case UnknownKey = 'unknown_key';

    case UnknownRuleId = 'unknown_rule_id';

    /**
     * The id names a real rule that does not answer in this suite.
     *
     * Its own kind rather than a flavor of {@see UnknownRuleId}, because the two send a reader to
     * different places. "No such rule" means look for a typo; "that rule exists, it just does not
     * run here" means look at which block the line is in. A message that conflated them would send
     * somebody hunting a spelling mistake in an id they had spelled correctly.
     */
    case RuleNotInSuite = 'rule_not_in_suite';

    case DottedLiteralKey = 'dotted_literal_key';

    case MissingKey = 'missing_key';

    /**
     * A schema key the config does not set, so the shipped default applies.
     *
     * NOT a violation, and the distinction is the whole decision behind it. `mergeConfigFrom()` is
     * a SHALLOW merge, so an application that published `config/sqlens.php` before a release added
     * a nested key has that key missing for good. Treating that as fatal meant a package release
     * could not be installed at all — every `sqlens:*` command exited on misconfiguration until
     * somebody re-copied the file by hand.
     *
     * The strictness that remains is ONE-SIDED and is the half that was doing the work: an UNKNOWN
     * key is still fatal, because a typo that silently enables nothing is the failure the validator
     * exists for. What is given up is spotting a published copy that dropped a whole section — and
     * that is not given up silently, which is what this kind is for.
     */
    case DefaultedKey = 'defaulted_key';

    case WrongType = 'wrong_type';

    case OutOfRange = 'out_of_range';

    /** The kind's message phrase, including the remedy where the cause is mechanical. */
    public function phrase(): string
    {
        return match ($this) {
            self::UnknownKey => 'unknown key',
            self::UnknownRuleId => 'unknown rule id (the rule keeps running; a suppression that names nothing suppresses nothing)',
            self::RuleNotInSuite => 'a rule that does not answer in this suite (the id is real; the block it was written into is the wrong one)',
            self::DottedLiteralKey => 'literal dotted key (Laravel config nests sections as arrays; it does not split a dotted key into one)',
            self::MissingKey => 'missing key (a published config section replaces the package default wholesale, so re-add every key of the section)',
            self::DefaultedKey => 'not set, so the shipped default applies (harmless; re-add the key to your published config if you meant to set it)',
            self::WrongType => 'wrong type',
            self::OutOfRange => 'value out of range',
        };
    }
}
