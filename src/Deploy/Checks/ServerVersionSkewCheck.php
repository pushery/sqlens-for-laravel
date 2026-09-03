<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Whether CI checked the migrations against the server the deploy is about to meet.
 *
 * ## The failure this exists to catch
 *
 * CI lints against a PINNED version, because a lint that asked the database would produce different
 * answers on different days and stop being reproducible. That pin is the whole reason `sqlens:lint`
 * is deterministic — and it is also a claim about a server CI never saw.
 *
 * When the pin and the real instance disagree, every version-aware rule checked the wrong world. A
 * rule that stayed silent because "this is fixed in 18" said nothing about a 16 that is about to
 * receive the migration. Nothing is red, nothing is missing, and the report is confidently wrong —
 * which is worse than no report, because somebody acted on it.
 *
 * ## Why a major skew is not a louder minor skew
 *
 * Minor versions do not move the rules: this package's version windows are declared in majors, so a
 * pin of 18.1 against a real 18.4 changes no verdict. It is still worth saying — the pin is stale
 * and will drift further — but it is a note, not a blocker.
 *
 * A major skew is a different claim entirely. It means the version windows were evaluated against a
 * server that does not exist here, and there is no way to know from the report alone which findings
 * that changed. So the severity difference is not a gradient of the same thing; it is two different
 * facts wearing one check id.
 */
final readonly class ServerVersionSkewCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.CONTEXT.VERSION_SKEW';

    /** @param list<string> $versionAwareRuleIds rules whose verdict depends on the server major */
    public function __construct(
        private ?string $pin = null,
        private array $versionAwareRuleIds = [],
    ) {}

    public function id(): string
    {
        return self::ID;
    }

    /** Both engines pin the same way, so both are asked. */
    public function appliesTo(string $driver): bool
    {
        return in_array($driver, ['pgsql', 'mysql'], true);
    }

    public function run(PreflightContext $context): CheckResult
    {
        $real = $context->serverVersion;

        if ($real->major === 0) {
            // Undetermined rather than "no skew". An unreadable version is not agreement — and
            // reporting it as one would be exactly the silent green this gate exists to refuse.
            return CheckResult::undetermined(
                self::ID,
                'the server did not answer with a version this build could read, so the pin could '
                .'not be compared against it. Nothing follows about whether CI checked the right '
                .'world: an unread version is not a matching one.',
            );
        }

        if ($this->pin === null || trim($this->pin) === '') {
            // A note, not a failure. Running without a pin is a legitimate choice — it just means
            // CI's answers moved with whatever server it met, and the person reading a report has
            // no way to know that unless somebody says so.
            return CheckResult::pass(self::ID, [$this->noPinFinding($context, $real)]);
        }

        $pinned = ServerVersion::parsePin($this->pin, $context->driver);

        if (! $pinned instanceof ServerVersion) {
            return CheckResult::undetermined(
                self::ID,
                sprintf(
                    'the configured `assume_server_version` pin "%s" is not a version this build '
                    .'understands, so nothing was compared. A pin that cannot be read is worse than '
                    .'none: it looks like determinism and provides none.',
                    $this->pin,
                ),
            );
        }

        if ($pinned->major === $real->major && $pinned->minor === $real->minor) {
            return CheckResult::pass(self::ID);
        }

        return $pinned->major === $real->major
            ? CheckResult::pass(self::ID, [$this->skewFinding($context, $pinned, $real, Severity::Low, false)])
            : CheckResult::fail(self::ID, [$this->skewFinding($context, $pinned, $real, Severity::High, true)]);
    }

    private function skewFinding(
        PreflightContext $context,
        ServerVersion $pinned,
        ServerVersion $real,
        Severity $severity,
        bool $majorSkew,
    ): Finding {
        $affected = $majorSkew ? $this->versionAwareRuleIds : [];

        $message = sprintf(
            'CI checked these migrations against %s, and this server is %s. %s',
            $pinned->toString(),
            $real->toString(),
            $majorSkew
                ? sprintf(
                    'The majors differ, so every version-aware rule was evaluated against a server '
                    .'that is not this one — %s. Pin the real major, or run the lint against it.',
                    $affected === []
                        ? 'this build declares no version-aware rules, so nothing changed hands this time'
                        : 'affected rules: '.implode(', ', $affected),
                )
                : 'The majors agree, so no verdict changed. The pin is stale and will drift further.',
        );

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: $message,
            location: Location::inCatalog($context->driver, $context->connection, 'server version', SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: $severity,
            // Nothing about a skew makes a deploy slower or locks anything — it makes the REPORT
            // wrong. Saying `online` here is honest and keeps the downtime axis meaning what it says.
        )->withDowntimeClass(DowntimeClass::Online);
    }

    private function noPinFinding(PreflightContext $context, ServerVersion $real): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'No `assume_server_version` is configured, so CI checked these migrations against '
                .'whatever server it happened to meet, and this deploy targets %s. That is a valid '
                .'way to run — it just means a lint result is only reproducible where the servers '
                .'agree, and nothing in the report would have said so.',
                $real->toString(),
            ),
            location: Location::inCatalog($context->driver, $context->connection, 'server version', SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Info,
        )->withDowntimeClass(DowntimeClass::Online);
    }
}
