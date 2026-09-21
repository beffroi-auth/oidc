<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;

/**
 * Where the endpoints of a tenant are served to a client that presents a certificate (RFC 8705 §5). A
 * deployment serves them on a host whose TLS listener asks for one, which is infrastructure and
 * therefore the integration's to know (architecture §5.2, docs/mtls-at-the-edge.md); a deployment that
 * has no such host locates none, and the document announces no alias.
 */
interface MutualTlsEndpointLocatorInterface
{
    public function locateMutualTls(Tenant $tenant): ?ProviderEndpoints;
}
