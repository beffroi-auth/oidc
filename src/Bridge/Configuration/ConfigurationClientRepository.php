<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_key_exists;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequirementInterface;
use WeakMap;

/**
 * The clients declared in the configuration (architecture §4.1, §5.1): validated at boot, the secret hashed
 * on the first lookup. The clients are built per tenant instance, so that a client always points at the
 * tenant of the request that asked for it.
 */
final class ConfigurationClientRepository implements ClientRepositoryInterface, PushedAuthorizationRequirementInterface
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
        CertificateReaderInterface $certificates,
    ) {
        foreach ($definitions as $clientId => $definition) {
            $this->definitions[$clientId] = ClientDefinition::fromArray((string) $clientId, $definition, $algorithms, $methods, $certificates);
        }
        $this->clients = new WeakMap();
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        if ($tenant->slug !== $this->tenantSlug || ! isset($this->definitions[$clientId])) {
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

    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenFormat $format): bool
    {
        if ($tenant->slug !== $this->tenantSlug) {
            return false;
        }
        return array_any($this->definitions, fn ($definition) => $definition->accessTokenFormat === $format);
    }

    /**
     * RFC 9126 §5: the document says so when every client declared here does, which is what makes it the
     * truth about the endpoint and not a second place to keep in agreement (issue #98). A tenant nothing
     * is declared for requires nothing of anybody.
     */
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool
    {
        if ($tenant->slug !== $this->tenantSlug || $this->definitions === []) {
            return false;
        }

        return array_all($this->definitions, static fn (ClientDefinition $definition): bool => $definition->requiresPushedAuthorizationRequests);
    }
}
