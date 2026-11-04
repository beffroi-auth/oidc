<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * A record that stores its client's identifier only and resolves the client on every load. A record whose client
 * is no longer registered keeps the "client" property uninitialised.
 */
interface ResolvesItsClientInterface
{
    public Tenant $tenant { get; }

    public string $clientId { get; }

    /**
     * The object whose "client" property is resolved: the record itself or a value it keeps.
     */
    public function clientHolder(): object;
}
