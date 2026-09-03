<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * The transaction context a canonical statement runs in — retrievable off the
 * canonical form so a lock-hygiene rule can reason about whether a statement is
 * inside a transaction, without knowing a thing about Laravel's migrator. It
 * carries the mode and, for an undetermined (or a reasoned `None`), the reason.
 *
 * Built through the named constructors so the mode and its reason stay consistent
 * (an Undetermined always carries a reason). `withinTransaction()` is the plain
 * yes/no a rule usually wants — true ONLY when the statement definitely runs in a
 * transaction, so an undetermined context never reads as "yes".
 */
final readonly class TransactionContext
{
    public function __construct(
        public TransactionMode $mode,
        public ?string $reason = null,
    ) {}

    public static function implicitMigratorTransaction(): self
    {
        return new self(TransactionMode::ImplicitMigratorTransaction);
    }

    public static function explicitTransaction(): self
    {
        return new self(TransactionMode::ExplicitTransaction);
    }

    public static function none(?string $reason = null): self
    {
        return new self(TransactionMode::None, $reason);
    }

    public static function undetermined(string $reason): self
    {
        return new self(TransactionMode::Undetermined, $reason);
    }

    /**
     * The plain migrator-flag derivation, used as a fallback when the resolver stage
     * is not part of the pipeline (an isolated stage run). The resolver itself
     * refines this with the driver capability and the stream markers.
     */
    public static function fromMigratorFlag(bool $withinTransaction): self
    {
        return $withinTransaction ? self::implicitMigratorTransaction() : self::none();
    }

    /** True only when the statement definitely runs inside a transaction. */
    public function withinTransaction(): bool
    {
        return $this->mode === TransactionMode::ImplicitMigratorTransaction
            || $this->mode === TransactionMode::ExplicitTransaction;
    }
}
