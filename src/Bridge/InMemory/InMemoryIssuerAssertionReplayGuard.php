<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use function sprintf;

/**
 * One process only: workers that share no store would each accept the same assertion.
 */
final class InMemoryIssuerAssertionReplayGuard implements IssuerAssertionReplayGuardInterface
{
    /**
     * @var array<string, DateTimeImmutable> until when each identifier is remembered
     */
    public private(set) array $seen = [];

    public function remember(Tenant $tenant, TrustedIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $key = sprintf('%s|%s|%s', $tenant->id->toRfc4122(), $issuer->issuer, $jti);
        if (isset($this->seen[$key])) {
            return false;
        }
        $this->seen[$key] = $expiresAt;

        return true;
    }
}
