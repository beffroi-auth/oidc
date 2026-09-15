<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;

/**
 * The discovery endpoint (OIDC Discovery §4, architecture §4.8): the metadata of a tenant, assembled from
 * its issuer, the endpoints the integration serves it at, and what the claims provider announces (§3
 * "scopes_supported" and "claims_supported"), "offline_access" (OIDC Core §11) being the provider's own
 * and "openid" the document's. Everything else in the document is fixed by the module. Nothing is
 * written, nothing is announced: this is a read of the configuration.
 */
final readonly class DiscoveryHandler
{
    /**
     * @param int $maxAge how long a client may cache the document, in seconds; one hour by default, what oidc_login keeps it anyway
     */
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ClaimsProviderInterface $claims,
        private int $maxAge = 3600,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
    }

    public function handle(Tenant $tenant): ProviderMetadata
    {
        return new ProviderMetadata(
            $tenant->issuer,
            $this->endpoints->locate($tenant),
            [...$this->claims->supportedScopes(), new Scope('offline_access')],
            $this->claims->supportedClaims(),
            $this->maxAge,
        );
    }
}
