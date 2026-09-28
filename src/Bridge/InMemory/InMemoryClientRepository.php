<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Heidi\Oidc\Port\RegisteredResourcesInterface;
use Heidi\Oidc\Port\RegisteredScopesInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryClientRepository implements
    ClientRepositoryInterface,
    PushedAuthorizationRequirementInterface,
    RegisteredAccessTokenShapesInterface,
    RegisteredResourcesInterface,
    RegisteredScopesInterface,
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

    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenShapeInterface $shape): bool
    {
        return array_any(
            $this->clients,
            static fn (Client $client): bool => $client->belongsTo($tenant) && $client->registration->accessTokenShape->name() === $shape->name(),
        );
    }

    /**
     * RFC 8707 §2: what the clients of the tenant registered, each resource named once.
     */
    public function resourcesRegisteredIn(Tenant $tenant): array
    {
        $resources = [];
        foreach ($this->clients as $client) {
            if (! $client->belongsTo($tenant)) {
                continue;
            }
            foreach ($client->registration->resources as $resource) {
                if (! array_any($resources, static fn (ResourceIndicator $kept): bool => $kept->equals($resource))) {
                    $resources[] = $resource;
                }
            }
        }

        return $resources;
    }

    /**
     * OIDC Discovery §3: what the clients of the tenant registered, each scope named once.
     */
    public function scopesRegisteredIn(Tenant $tenant): array
    {
        $scopes = [];
        foreach ($this->clients as $client) {
            if (! $client->belongsTo($tenant)) {
                continue;
            }
            foreach ($client->registration->allowedScopes as $scope) {
                if (! array_any($scopes, static fn (Scope $kept): bool => $kept->equals($scope))) {
                    $scopes[] = $scope;
                }
            }
        }

        return $scopes;
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
