<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use function sprintf;

/**
 * The "jti" already seen, kept for the life of the process. What a single-process integration and the
 * tests use; a deployment of several workers points the port at a store they share, or one worker would
 * register a client on a statement another one already registered one on.
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
