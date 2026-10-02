<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;

/**
 * Remembers the "jti" of an assertion a trusted issuer signed until it expires (RFC 7523 §3), so that one
 * assertion is exchanged for a token once. The store outlives the request and is shared by the workers of a
 * deployment: an assertion replayed on another worker is a replay all the same.
 *
 * It is not the guard of the assertions that authenticate a client (ClientAssertionReplayGuardInterface): the
 * two readings of an assertion never share anything, so that one accepted as an authorization cannot be
 * accepted as an authentication by having been remembered in the same place (RFC 7523 §2.1).
 */
interface IssuerAssertionReplayGuardInterface
{
    /**
     * @param string $jti the identifier of the assertion, unique to the issuer that signed it
     * @param DateTimeImmutable $expiresAt when the assertion stops being valid, after which it may be forgotten
     *
     * @return bool true when the identifier had not been seen and is now remembered, false when it had
     */
    public function remember(Tenant $tenant, TrustedIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool;
}
