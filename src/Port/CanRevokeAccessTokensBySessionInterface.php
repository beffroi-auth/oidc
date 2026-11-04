<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

interface CanRevokeAccessTokensBySessionInterface
{
    /**
     * @return list<StoredAccessToken>
     */
    public function revokeBySession(Uuid $session): array;
}
