<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;

/**
 * A companion of AccessTokenRepositoryInterface: one token back, for the revocation endpoint (RFC 7009 §2.1).
 */
interface CanRevokeAccessTokenInterface
{
    public function revoke(StoredAccessToken $token): void;
}
