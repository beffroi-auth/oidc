<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use function sprintf;

/**
 * The "jti" already seen, kept for the life of the process. What a single-process integration and the tests
 * use; a deployment of several workers points the port at a store they share, or one worker would exchange an
 * assertion another one already exchanged.
 */
final class InMemoryIssuerAssertionReplayGuard implements IssuerAssertionReplayGuardInterface
{
    /**
     * @var array<string, DateTimeImmutable>
     */
    private array $seen = [];

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
