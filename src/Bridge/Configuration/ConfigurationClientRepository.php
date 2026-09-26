<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_key_exists;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\PresentedTokenTypesInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use Heidi\Oidc\Port\RegisteredAccessTokenShapesInterface;
use Heidi\Oidc\Port\RegisteredResourcesInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedDeliveryModesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;
use Heidi\Oidc\Port\UnsignedRequestObjectsInterface;
use WeakMap;

/**
 * The clients declared in the configuration (architecture §4.1, §5.1): validated at boot, the secret hashed
 * on the first lookup. The clients are built per tenant instance, so that a client always points at the
 * tenant of the request that asked for it.
 */
final class ConfigurationClientRepository implements
    ClientRepositoryInterface,
    PushedAuthorizationRequirementInterface,
    RegisteredAccessTokenShapesInterface,
    RegisteredResourcesInterface,
    UnsignedRequestObjectsInterface
{
    /**
     * @var array<string, ClientDefinition>
     */
    private array $definitions = [];

    /**
     * @var array<string, ClientSecretInterface|null> by client identifier
     */
    private array $secrets = [];

    /**
     * @var WeakMap<Tenant, array<string, Client>>
     */
    private WeakMap $clients;

    /**
     * @param array<string, array<string, mixed>> $definitions by client identifier
     */
    public function __construct(
        private readonly string $tenantSlug,
        array $definitions,
        private readonly PasswordHasherInterface $hasher,
        SignatureAlgorithmsInterface $algorithms,
        ClientAuthenticationMethodsInterface $methods,
        ServedGrantsInterface $grants,
        ServedAccessTokenShapesInterface $shapes,
        CertificateReaderInterface $certificates,
        KeyEncryptionAlgorithmsInterface $keyEncryption,
        ContentEncryptionAlgorithmsInterface $contentEncryption,
        ServedDeliveryModesInterface $deliveryModes,
        PresentedTokenTypesInterface $tokenTypes,
    ) {
        foreach ($definitions as $clientId => $definition) {
            $this->definitions[$clientId] = ClientDefinition::fromArray(
                (string) $clientId,
                $definition,
                $algorithms,
                $methods,
                $grants,
                $shapes,
                $certificates,
                $keyEncryption,
                $contentEncryption,
                $deliveryModes,
                $tokenTypes,
            );
        }
        $this->clients = new WeakMap();
    }

    /**
     * The clients declared here are those of one tenant, named by its slug: anything asked about another
     * tenant is asked of the repository that holds its clients, and answered here as if there were none.
     */
    private function serves(Tenant $tenant): bool
    {
        return $tenant->slug === $this->tenantSlug;
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        if (! $this->serves($tenant) || ! isset($this->definitions[$clientId])) {
            return null;
        }
        $clients = $this->clients[$tenant] ?? [];
        if (! isset($clients[$clientId])) {
            $definition = $this->definitions[$clientId];
            if (! array_key_exists($clientId, $this->secrets)) {
                $this->secrets[$clientId] = $definition->hasSecret() ? $definition->keepSecret($this->hasher) : null;
            }
            $clients[$clientId] = $definition->toClient($tenant, $this->secrets[$clientId]);
            $this->clients[$tenant] = $clients;
        }

        return $clients[$clientId];
    }

    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenShapeInterface $shape): bool
    {
        if (! $this->serves($tenant)) {
            return false;
        }

        return array_any(
            $this->definitions,
            static fn (ClientDefinition $definition): bool => $definition->registration->accessTokenShape->name() === $shape->name(),
        );
    }

    /**
     * RFC 8707 §2: what the clients declared here may ask a token for, which is what the document
     * enumerates (RFC 9728 §4) and nothing kept beside them (issue #98).
     */
    public function resourcesRegisteredIn(Tenant $tenant): array
    {
        if (! $this->serves($tenant)) {
            return [];
        }
        $resources = [];
        foreach ($this->definitions as $definition) {
            foreach ($definition->registration->resources as $resource) {
                if (! array_any($resources, static fn (ResourceIndicator $kept): bool => $kept->equals($resource))) {
                    $resources[] = $resource;
                }
            }
        }

        return $resources;
    }

    /**
     * RFC 9126 §5: the document says so when every client declared here does, which is what makes it the
     * truth about the endpoint and not a second place to keep in agreement (issue #98). A tenant nothing
     * is declared for requires nothing of anybody.
     */
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool
    {
        if (! $this->serves($tenant) || $this->definitions === []) {
            return false;
        }

        return array_all($this->definitions, static fn (ClientDefinition $definition): bool => $definition->registration->requiresPushedAuthorizationRequests);
    }

    /**
     * OIDC Registration §2: the document announces "none" when a client declared here registered it, so
     * that what is announced is what a client of this tenant may actually send (issue #98).
     */
    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool
    {
        if (! $this->serves($tenant)) {
            return false;
        }

        return array_any($this->definitions, static fn (ClientDefinition $definition): bool => $definition
            ->registration
            ->requestObjectSigning
            ->acceptsUnsigned());
    }
}
