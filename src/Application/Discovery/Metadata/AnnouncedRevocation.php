<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7009 §2 through RFC 8414 §2: where a token is revoked, and how the caller authenticates there,
 * which is how it authenticates at the token endpoint.
 */
final readonly class AnnouncedRevocation implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ClientAuthenticationMethodsInterface $methods,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $methods = $this->methods->clientAuthenticationMethods();

        return [
            'revocation_endpoint' => $this->endpoints->locate($tenant)->revocation,
            'revocation_endpoint_auth_methods_supported' => array_map(
                static fn (ClientAuthenticationMethodInterface $method): string => $method->name(),
                $methods,
            ),
            'revocation_endpoint_auth_signing_alg_values_supported' => $this->algorithms->assertionSigning($methods),
        ];
    }
}
