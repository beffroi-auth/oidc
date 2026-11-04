<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;

interface ActiveConsentsInterface
{
    /**
     * @return list<Consent> most recently granted first
     */
    public function activeOf(User $user): array;
}
