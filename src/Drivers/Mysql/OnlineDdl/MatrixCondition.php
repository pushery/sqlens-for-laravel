<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * A single condition under which a matrix entry's classification holds — the edge the
 * SQL alone does not show (an instant add falling back to a rebuild after enough row
 * versions, a charset change only being cheap when the storage size stays the same).
 *
 * It carries its own stable id and its own prose, so the reasoning can be cited without
 * quoting the MySQL manual.
 */
final readonly class MatrixCondition
{
    public function __construct(
        public string $id,
        public string $text,
    ) {}
}
