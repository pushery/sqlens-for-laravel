<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

use Attribute;
use Pushery\SQLens\Deploy\PrivilegeClass;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * "The `DO` blocks of this migration need this right on this object, and here is why."
 *
 * ## The question a `DO` block leaves open
 *
 * `DEPLOY.PREFLIGHT.MISSING_PRIVILEGE` asks, before a deploy, whether the migration role may do what
 * the pending migrations do. A `DO` block runs code, and what the role must be allowed to do depends
 * on what that code does, which reading the statement cannot tell. Without an answer the check ends
 * undetermined, and the only way past it was the waiver on `privilege_check_incomplete`, which opens
 * the deploy for every other open question as well.
 *
 * The migration's author knows the answer. This attribute writes it down where the block is, and
 * the check asks the database about each right it names instead of the block, exactly as it asks
 * about a statement it can read.
 *
 * ## It answers the blocks of its own migration, and nothing else
 *
 * A declaration replaces the open question of each `DO` block in the migration it sits on. A `DO`
 * block in another pending migration stays open, and so does any other statement the check cannot
 * read in this one: the attribute speaks about code blocks, not about the migration as a whole.
 *
 * ## Repeatable, one right per attribute
 *
 * A block that touches several objects needs one declaration per object and right. The pre-scan
 * reads the attribute from the source and never instantiates it, so only literal values count: the
 * object as a string, the type and the class as cases of their enums. A declaration whose reason is
 * missing, empty or only whitespace answers nothing, by the rule {@see AttributeReason} holds for
 * every attribute, and the block stays open.
 *
 * ```php
 * return new class extends Migration
 * {
 *     #[DoBlockPrivilege('public.billing_invoices', SchemaObjectType::Table, PrivilegeClass::Trigger,
 *         reason: 'the block recreates the trigger that pins the search path of the invoice function')]
 *     public function up(): void
 *     {
 *         DB::statement('DO $$ BEGIN … END $$');
 *     }
 * };
 * ```
 *
 * On the class it reads `return new #[DoBlockPrivilege(…)] class extends Migration`, and it then
 * answers the blocks of `up()` the same way.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
final readonly class DoBlockPrivilege
{
    /**
     * @param  string  $object  the object the block needs the right on, qualified the way the check
     *                          names a target, e.g. `public.billing_invoices`
     * @param  SchemaObjectType  $type  what kind of object it is
     * @param  PrivilegeClass  $privilege  the right the block needs on it
     * @param  string  $reason  why the block needs it. One that is empty or only whitespace is not
     *                          one, and the declaration is treated as though it were absent.
     */
    public function __construct(
        public string $object,
        public SchemaObjectType $type,
        public PrivilegeClass $privilege,
        public string $reason,
    ) {}
}
