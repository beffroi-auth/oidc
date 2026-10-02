<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;

/**
 * Where the endpoints of a tenant are served to a client that presents a certificate (RFC 8705 §5). A
 * deployment serves them on a host whose TLS listener asks for one, which is infrastructure and
 * therefore the integration's to know (architecture §5.2); a deployment that
 * has no such host locates none, and the document announces no alias.
 */
interface MutualTlsEndpointLocatorInterface
{
    /**
     * @throws LogicException when the routes are not mounted where the issuer of the tenant makes
     *                        clients look for them (OIDC Discovery §4.1)
     */
    public function locateMutualTls(Tenant $tenant): ?ProviderEndpoints;
}
