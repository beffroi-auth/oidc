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
 * Clients are built per tenant instance, so that a client always points at the tenant of the request that asked.
 */
final class ConfigurationClientRepository implements ClientInventoryInterface, ClientSourceInterface
{
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

    public function registrationsIn(Tenant $tenant): iterable
    {
        if (! $this->serves($tenant)) {
            return;
        }
        foreach ($this->definitions as $definition) {
            yield $definition->registration;
        }
    }

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
