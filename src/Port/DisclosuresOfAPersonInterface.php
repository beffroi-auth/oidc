<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Symfony\Component\Uid\Uuid;

interface DisclosuresOfAPersonInterface
{
    /**
     * @param Uuid|null $after the last row the caller read, null for the first page
     *
     * @return list<Disclosure> oldest first
     */
    public function everyDisclosureTo(User $user, int $howMany, ?Uuid $after = null): array;
}
