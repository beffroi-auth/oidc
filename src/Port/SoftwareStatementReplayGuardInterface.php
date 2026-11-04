<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;

/**
 * RFC 7591 §2.3
 *
 * Shared by the workers of a deployment, and never with the guards of assertions (RFC 7523 §2.1).
 */
interface SoftwareStatementReplayGuardInterface
{
    /**
     * @return bool false when the identifier was already remembered
     */
    public function remember(Tenant $tenant, StatementIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool;
}
