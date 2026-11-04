<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use function sprintf;

/**
 * One process only: workers that share no store would each accept the same software statement.
 */
final class InMemorySoftwareStatementReplayGuard implements SoftwareStatementReplayGuardInterface
{
    /**
     * @var array<string, DateTimeImmutable>
     */
    private array $seen = [];

    public function remember(Tenant $tenant, StatementIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $key = sprintf('%s|%s|%s', $tenant->id->toRfc4122(), $issuer->issuer, $jti);
        if (isset($this->seen[$key])) {
            return false;
        }
        $this->seen[$key] = $expiresAt;

        return true;
    }
}
