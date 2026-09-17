<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\StoredAccessToken;

/**
 * A companion of AccessTokenRepositoryInterface: the store can take one token back, which the revocation
 * endpoint does when a client gives one (RFC 7009 §2.1). A revoked token is an unknown one from then on;
 * the event of the caller is the trace.
 */
interface CanRevokeAccessTokenInterface
{
    public function revoke(StoredAccessToken $token): void;
}
