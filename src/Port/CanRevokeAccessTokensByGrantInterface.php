<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * A companion of AccessTokenRepositoryInterface: the store can take back every token descending from a
 * grant, which the replay of the code asks for (RFC 6749 §4.1.2), and so does the revocation of a refresh
 * token of that grant (RFC 7009 §2.1).
 */
interface CanRevokeAccessTokensByGrantInterface
{
    /**
     * @return list<StoredAccessToken> the records removed
     */
    public function revokeByGrant(Uuid $grantId): array;
}
