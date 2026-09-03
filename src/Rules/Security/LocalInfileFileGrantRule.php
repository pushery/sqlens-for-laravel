<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * `local_infile` is on AND an account on this instance holds `FILE` — the two halves of a path.
 *
 * The escalation of {@see LocalInfileRule}, and a second rule id rather than a second severity,
 * because severity is metadata on the RULE here. That is not a technicality: the two say different
 * sentences, and the deduplication key is rule id AND location, so both survive into one report —
 * which is only right if a reader learns something from the second.
 *
 * They do. `local_infile` alone says the server would ask a CLIENT for a file, which needs a hostile
 * or hijacked server to matter and touches nothing on the database host. `FILE` alone says an account
 * can read and write files as the SERVER's operating-system user, bounded by `secure_file_priv`.
 * Together they are a route: a connection that can be induced to upload a file, and an account that
 * can place one where the host will read it.
 *
 * ## Why the unreadable case is the reason this rule exists at all
 *
 * The grant tables are refusable, and on a managed MySQL a refused read is the ORDINARY case rather
 * than the exception. An escalation that simply did not fire there would be indistinguishable from
 * one that correctly found no such account — the same silence, two opposite meanings, and the one a
 * reader assumes is the reassuring one.
 *
 * So the fact is DECLARED through {@see self::requiredCrossFacts()}, and the base turns a fact the
 * collector could not measure into `undetermined` with the collector's own named reason. The
 * `medium` finding from the rule next door still stands beside it: the run says "the capability is
 * on" and "whether an account could exploit it could not be established", which is two true
 * sentences where a silent non-escalation would have been one misleading absence.
 */
final class LocalInfileFileGrantRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.LOCAL_INFILE_FILE_GRANT';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::High;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'local_infile';
    }

    /**
     * The grant fact, declared so the base can enforce the honesty this rule turns on.
     *
     * @return list<string>
     */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [SettingCrossFacts::FILE_PRIVILEGE_ACCOUNTS];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Same acceptance as the rule this escalates, deliberately duplicated rather than shared: a
        // spelling difference is not a state difference, and a config file may write either.
        if (! in_array(strtolower(trim($serverValue)), ['on', '1', 'true', 'yes'], true)) {
            return null;
        }

        $accounts = $this->crossFact($object, SettingCrossFacts::FILE_PRIVILEGE_ACCOUNTS);

        // Measured and empty is a real answer, and the counter-arm of this whole rule: the capability
        // is on, nobody here can act on the other end, and the `medium` finding next door is the
        // right weight. Reaching this line at all means the read SUCCEEDED — the base has already
        // turned an unreadable fact into `undetermined` with its reason.
        if ($accounts === null || trim($accounts) === '') {
            return null;
        }

        return sprintf(
            'local_infile is %s AND this instance carries an account holding FILE (%s), which are the '
            .'two halves of one route rather than two separate settings. On its own the capability '
            .'needs a hostile or hijacked server to matter and touches nothing on the database host; '
            .'on its own FILE is bounded by secure_file_priv and needs somebody holding that account. '
            .'Together a connection that can be induced to upload a file meets an account that can '
            .'place one where the host will read it. Reported beside SEC.CFG.LOCAL_INFILE rather than '
            .'instead of it: that one is about the server\'s capability, this one about what exists '
            .'on this instance alongside it. %s',
            $serverValue,
            $accounts,
            $this->remediation($expectation),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the RUNNING value, not the file: a setting changed on disk and not yet reloaded is invisible here, and one changed only for this session would be read as the server\'s',
            'reads the setting and the grant, and cannot tell whether the account holding the grant is one anything actually connects as — a provisioning account that exists and is never used carries the same catalog rows as one in daily use',
        ];
    }
}
