<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\ServedAccessTokenFormatsInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryClientRepository implements
    ClientRepositoryInterface,
    PushedAuthorizationRequirementInterface,
    ServedAccessTokenFormatsInterface,
    UnsignedRequestObjectsInterface
{
    /**
     * @var list<Client>
     */
    private array $clients = [];

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        foreach ($this->clients as $client) {
            if ($client->belongsTo($tenant) && $client->registration->clientId === $clientId) {
                return $client;
            }
        }

        return null;
    }

    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenFormat $format): bool
    {
        return array_any(
            $this->clients,
            static fn (Client $client): bool => $client->belongsTo($tenant) && $client->registration->accessTokenFormat === $format,
        );
    }

    /**
     * RFC 9126 §5: a tenant with no client of its own requires nothing of anybody.
     */
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool
    {
        $registered = array_filter($this->clients, static fn (Client $client): bool => $client->belongsTo($tenant));

        return $registered !== [] && array_all($registered, static fn (Client $client): bool => $client->registration->requiresPushedAuthorizationRequests);
    }

    /**
     * OIDC Registration §2: what one client of the tenant registered is what the document announces.
     */
    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool
    {
        return array_any(
            $this->clients,
            static fn (Client $client): bool => $client->belongsTo($tenant) && $client->registration->requestObjectSigning->acceptsUnsigned(),
        );
    }

    public function save(Client $client): void
    {
        $this->clients[] = $client;
    }
}
