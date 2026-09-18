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
 * The discovery endpoint (OIDC Discovery §4, architecture §4.8): the issuer, the endpoints, what the claims
 * provider announces; everything else is fixed by the module.
 */
final readonly class DiscoveryHandler
{
    /**
     * @param int $maxAge how long a client may cache the document, in seconds
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
