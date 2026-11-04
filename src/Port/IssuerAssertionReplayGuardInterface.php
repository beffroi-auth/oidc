<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;

/**
 * RFC 7523 §3
 *
 * Shared by the workers of a deployment, and never with the guard of client assertions (RFC 7523 §2.1).
 */
interface IssuerAssertionReplayGuardInterface
{
    /**
     * @return bool false when the identifier was already remembered
     */
    public function remember(Tenant $tenant, TrustedIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool;
}
