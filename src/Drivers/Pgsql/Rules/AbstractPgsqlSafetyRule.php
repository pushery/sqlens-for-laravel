<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules;

use Pushery\SQLens\Rules\AbstractSafetyRule;

/**
 * The base of the PostgreSQL safety-rule family.
 *
 * Everything a rule needs — identity derivation, the canonical-only {@see judge()}/
 * {@see verdict()} seam, the finding's shape, the metadata defaults — lives on the
 * driver-neutral {@see AbstractSafetyRule} in Core, because none of it is PostgreSQL-
 * specific: the same base carries the MySQL family and the driver-neutral lifecycle
 * rules. This class adds nothing but a name, so the PG rules read as a family and a
 * future PG-only convention has one obvious home. The inherited `DOCUMENTATION_BASE`
 * constant and `slug()` helper stay reachable as `AbstractPgsqlSafetyRule::…`, so the
 * PG completeness test needs no change.
 */
abstract class AbstractPgsqlSafetyRule extends AbstractSafetyRule {}
