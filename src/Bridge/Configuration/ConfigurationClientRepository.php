<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use WeakMap;

/**
 * The clients of a tenant, declared in the bundle configuration (architecture §4.1 and §5.1). Definitions
 * are validated when the repository is built, so that a wrong one fails at boot; the secret of a client is
 * hashed the first time that client is looked up, then kept for the life of the process, because hashing
 * costs what a password hash costs and most requests never look a client up.
 *
 * The repository holds no tenant: it knows the slug its definitions belong to and builds the clients for
 * the tenant instance it is given, one set per instance, so that a client always points at the tenant of
 * the request that asked for it, whatever the integration does with tenant instances between requests.
 */
final class ConfigurationClientRepository implements ClientRepositoryInterface
{
    /**
     * @var array<string, ClientDefinition>
     */
    private array $definitions = [];

    /**
     * @var array<string, PasswordHash> the hashed secrets, by client identifier, hashed once
     */
    private array $secretHashes = [];

    /**
     * @var WeakMap<Tenant, array<string, Client>>
     */
    private WeakMap $clients;

    /**
     * @param string $tenantSlug the tenant the definitions belong to
     * @param array<string, array<string, mixed>> $definitions keyed by client identifier, as the configuration gives them
     */
    public function __construct(
        private readonly string $tenantSlug,
        array $definitions,
        private readonly PasswordHasherInterface $hasher,
    ) {
        foreach ($definitions as $clientId => $definition) {
            $this->definitions[$clientId] = ClientDefinition::fromArray((string) $clientId, $definition);
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
            $secretHash = $definition->hasSecret() ? ($this->secretHashes[$clientId] ??= $definition->hashSecret($this->hasher)) : null;
            $clients[$clientId] = $definition->toClient($tenant, $secretHash);
            $this->clients[$tenant] = $clients;
        }

        return $clients[$clientId];
    }
}
