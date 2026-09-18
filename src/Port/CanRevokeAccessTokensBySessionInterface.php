<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Symfony\Component\Uid\Uuid;

/**
 * A companion of AccessTokenRepositoryInterface: every token of a session, for its end (architecture §4.9).
 */
interface CanRevokeAccessTokensBySessionInterface
{
    /**
     * @return list<StoredAccessToken> the records removed
     */
    public function revokeBySession(Uuid $session): array;
}
