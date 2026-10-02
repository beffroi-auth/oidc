<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use function array_key_exists;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Port\ClientSourceInterface;
use WeakMap;

/**
 * The clients declared in the configuration (architecture §4.1, §5.1): validated at boot, the secret hashed
 * on the first lookup. The clients are built per tenant instance, so that a client always points at the
 * tenant of the request that asked for it.
 */
final class ConfigurationClientRepository implements ClientInventoryInterface, ClientSourceInterface
{
    /**
     * What this source calls itself where a person is shown where a client came from: these are the
     * clients of `beffroi.yaml`, and one goes away when its block does.
     */
    public const string SOURCE = 'configuration';

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
        ClientMetadataReader $reader,
    ) {
        foreach ($definitions as $clientId => $definition) {
            $this->definitions[$clientId] = ClientDefinition::fromArray((string) $clientId, $definition, $reader);
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

    /**
     * What this source holds for that tenant: the registrations it read at boot, in the order they were
     * declared. What the set of them means is read once, where every source is read (`RegisteredClients`).
     */
    public function registrationsIn(Tenant $tenant): iterable
    {
        if (! $this->serves($tenant)) {
            return;
        }
        foreach ($this->definitions as $definition) {
            yield $definition->registration;
        }
    }

    /**
     * A declaration was not registered on a day and has nobody's history behind it, so it carries neither
     * date: what it is, is what the configuration says today.
     */
    public function inventoryIn(Tenant $tenant): iterable
    {
        if (! $this->serves($tenant)) {
            return;
        }
        foreach ($this->definitions as $definition) {
            yield new InventoriedClient(
                self::SOURCE,
                $definition->registration->clientId,
                $definition->registration->presentation->name,
            );
        }
    }
}
