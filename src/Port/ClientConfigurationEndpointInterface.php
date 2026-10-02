<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;

/**
 * Where one client reads, replaces and deletes itself (RFC 7592 §3, "registration_client_uri"). It is an
 * endpoint of the tenant like every other, so routing belongs to the integration (architecture §5.2) and
 * the path is written there and nowhere else; what makes it its own port rather than one more member of
 * `ProviderEndpoints` is that it is the URL of one client and not of the tenant, as the endpoints located
 * on the host that asks for a certificate are their own port for being another origin
 * (`MutualTlsEndpointLocatorInterface`).
 */
interface ClientConfigurationEndpointInterface
{
    /**
     * @throws LogicException when the routes of the provider are not mounted where the issuer of the
     *                        tenant makes clients look for them (OIDC Discovery §4.1)
     */
    public function clientConfigurationFor(Tenant $tenant, string $clientId): string;
}
