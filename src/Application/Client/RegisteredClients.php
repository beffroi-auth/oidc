<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function array_all;
use function array_any;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\ClientSourceInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Heidi\Oidc\Port\RegisteredResourcesInterface;
use Heidi\Oidc\Port\RegisteredScopesInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * The clients of a tenant, read from every source the wiring holds and answered as one (architecture
 * §4.1): the clients a deployment declared, those that registered themselves, and whatever source comes
 * after them. Nothing downstream learns which source a client came from, and a source added later is a
 * class and a line of wiring.
 *
 * The questions about the **set** of clients of a tenant are answered here and nowhere else (issue #98):
 * which resources and which scopes exist for it, which shapes of access token it issues, whether every
 * client of it pushes its requests, and whether one of them reads an unsigned request object. A source
 * says what it holds and never what the set of them means, so a store that keeps its clients in rows
 * writes none of these rules a second time in the idiom of its store.
 *
 * An identifier belongs to one client of a tenant, whatever the source: the provider draws it and refuses
 * a draw any source already holds (`ClientIdentifierDrawer`), so the first source that carries it answers.
 */
final readonly class RegisteredClients implements
    ClientRepositoryInterface,
    PushedAuthorizationRequirementInterface,
    RegisteredAccessTokenShapesInterface,
    RegisteredResourcesInterface,
    RegisteredScopesInterface,
    UnsignedRequestObjectsInterface
{
    /**
     * @param iterable<ClientSourceInterface> $sources in the order they are wired, the configuration of
     *                                                 the deployment first
     */
    public function __construct(
        private iterable $sources,
    ) {
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        foreach ($this->sources as $source) {
            $client = $source->findByClientId($tenant, $clientId);
            if ($client !== null) {
                return $client;
            }
        }

        return null;
    }

    /**
     * RFC 8707 §2: what the clients of the tenant may ask a token for, which is what the document
     * enumerates (RFC 9728 §4), each resource named once.
     */
    public function resourcesRegisteredIn(Tenant $tenant): array
    {
        $resources = [];
        foreach ($this->registrationsIn($tenant) as $registration) {
            foreach ($registration->resources as $resource) {
                if (! array_any($resources, static fn (ResourceIndicator $kept): bool => $kept->equals($resource))) {
                    $resources[] = $resource;
                }
            }
        }

        return $resources;
    }

    /**
     * OIDC Discovery §3: the scopes the clients of the tenant registered, which is where a scope that
     * stands for no claim comes from (issue #278), each named once.
     */
    public function scopesRegisteredIn(Tenant $tenant): array
    {
        $scopes = [];
        foreach ($this->registrationsIn($tenant) as $registration) {
            foreach ($registration->allowedScopes as $scope) {
                if (! array_any($scopes, static fn (Scope $kept): bool => $kept->equals($scope))) {
                    $scopes[] = $scope;
                }
            }
        }

        return $scopes;
    }

    /**
     * Architecture §4.6: whether a client of this tenant receives its access tokens in that shape, which
     * is what says whether the provider writes one at all for it.
     */
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
     * RFC 9126 §5: the document says so when every client of the tenant does, which is what makes it the
     * truth about the endpoint and not a second place to keep in agreement (issue #98). A tenant no
     * source holds a client of requires nothing of anybody.
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

    /**
     * OIDC Registration §2: the document announces "none" when a client of the tenant registered it, so
     * that what is announced is what a client of this tenant may actually send (issue #98).
     */
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
