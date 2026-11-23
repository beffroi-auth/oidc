<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_all;
use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ClientSourceInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Beffroi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Beffroi\Oidc\Port\RegisteredResourcesInterface;
use Beffroi\Oidc\Port\RegisteredScopesInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;

final readonly class RegisteredClients implements
    ClientRepositoryInterface,
    PushedAuthorizationRequirementInterface,
    RegisteredAccessTokenShapesInterface,
    RegisteredResourcesInterface,
    RegisteredScopesInterface,
    UnsignedRequestObjectsInterface
{
    /**
     * @param iterable<ClientSourceInterface> $sources the deployment's configuration first
     */
    public function __construct(
        private iterable $sources,
    ) {
    }

    /**
     * No source is asked for an identifier no registration may carry: a database refuses bytes that are not text.
     */
    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        if (! ClientRegistration::isClientIdentifier($clientId)) {
            return null;
        }
        foreach ($this->sources as $source) {
            $client = $source->findByClientId($tenant, $clientId);
            if ($client !== null) {
                return $client;
            }
        }

        return null;
    }

    public function resourcesRegisteredIn(Tenant $tenant): array
    {
        $resources = [];
        foreach ($this->registrationsIn($tenant) as $registration) {
            foreach ($registration->resources as $resource) {
                $resources[$resource->value] ??= $resource;
            }
        }

        return array_values($resources);
    }

    public function scopesRegisteredIn(Tenant $tenant): array
    {
        $scopes = [];
        foreach ($this->registrationsIn($tenant) as $registration) {
            foreach ($registration->allowedScopes as $scope) {
                $scopes[$scope->value] ??= $scope;
            }
        }

        return array_values($scopes);
    }

    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenShapeInterface $shape): bool
    {
        foreach ($this->registrationsIn($tenant) as $registration) {
            if ($registration->accessTokenShape->name() === $shape->name()) {
                return true;
            }
        }

        return false;
    }

    /**
     * RFC 9126 §5
     */
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool
    {
        $registrations = [...$this->registrationsIn($tenant)];

        return (
            $registrations !== []
            && array_all(
                $registrations,
                static fn (ClientRegistration $registration): bool => $registration->requiresPushedAuthorizationRequests,
            )
        );
    }

    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool
    {
        foreach ($this->registrationsIn($tenant) as $registration) {
            if ($registration->requestObjectSigning->acceptsUnsigned()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return iterable<ClientRegistration>
     */
    private function registrationsIn(Tenant $tenant): iterable
    {
        foreach ($this->sources as $source) {
            yield from $source->registrationsIn($tenant);
        }
    }
}
