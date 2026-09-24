<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3: who the provider is and where its four endpoints are. Every provider has these,
 * whatever else it is wired with.
 */
final readonly class ProviderIdentity implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $endpoints = $this->endpoints->locate($tenant);

        return [
            'issuer' => $tenant->issuer->value,
            'authorization_endpoint' => $endpoints->authorization,
            'token_endpoint' => $endpoints->token,
            'userinfo_endpoint' => $endpoints->userinfo,
            'jwks_uri' => $endpoints->jwks,
        ];
    }
}
