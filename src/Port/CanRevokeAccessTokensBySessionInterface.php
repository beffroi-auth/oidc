<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * A companion of AccessTokenRepositoryInterface: the store can take back every token issued in a session,
 * which the end of the session asks for (decision 0006, architecture §4.9).
 */
interface CanRevokeAccessTokensBySessionInterface
{
    /**
     * @return list<StoredAccessToken> the records removed
     */
    public function revokeBySession(Uuid $session): array;
}
