<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * A companion of AccessTokenRepositoryInterface: every token of a grant, for a replayed code (RFC 6749
 * §4.1.2) or a revoked refresh token (RFC 7009 §2.1).
 */
interface CanRevokeAccessTokensByGrantInterface
{
    /**
     * @return list<StoredAccessToken> the records removed
     */
    public function revokeByGrant(Uuid $grantId): array;
}
