<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Administration;

use Beffroi\Core\Domain\Group\Group;

/**
 * A group of the tenant as an administrator lists it: how many members it holds, which delivers none of them, and
 * whether its members administer the tenant (decision 0038).
 */
final readonly class CountedGroup
{
    public function __construct(
        public Group $group,
        public int $members,
        public bool $administers,
    ) {
    }
}
