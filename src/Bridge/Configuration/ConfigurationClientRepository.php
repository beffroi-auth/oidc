<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientRepositoryInterface;

/**
 * The clients of a tenant, declared in the bundle configuration (architecture §4.1 and §5.1). Definitions
 * are validated when the repository is built, so that a wrong one fails at boot; the secret of a client is
 * hashed the first time that client is looked up, then kept for the life of the process, because hashing
 * costs what a password hash costs and most requests never look a client up.
 */
final class ConfigurationClientRepository implements ClientRepositoryInterface
{
    /**
     * @var array<string, ClientDefinition>
     */
    private array $definitions = [];

    /**
     * @var array<string, Client>
     */
    private array $clients = [];

    /**
     * @param array<string, array<string, mixed>> $definitions keyed by client identifier, as the configuration gives them
     */
    public function __construct(
        private readonly Tenant $tenant,
        array $definitions,
        private readonly PasswordHasherInterface $hasher,
    ) {
        foreach ($definitions as $clientId => $definition) {
            $this->definitions[$clientId] = ClientDefinition::fromArray((string) $clientId, $definition);
        }
    }

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        if (! $tenant->equals($this->tenant) || ! isset($this->definitions[$clientId])) {
            return null;
        }

        return $this->clients[$clientId] ??= $this->definitions[$clientId]->toClient($this->tenant, $this->hasher);
    }
}
