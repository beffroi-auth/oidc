<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.1.2, RFC 7009 §2.1
 */
interface CanRevokeAccessTokensByGrantInterface
{
    /**
     * @return list<StoredAccessToken>
     */
    public function revokeByGrant(Uuid $grantId): array;
}
