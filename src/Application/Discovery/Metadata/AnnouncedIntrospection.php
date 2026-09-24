<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_filter;
use function array_values;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\MethodNames;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7662 §2 and RFC 9701 §6: where a token is introspected, how the caller authenticates there, and
 * what a signed introspection response is signed with. Only the methods that authenticate the caller are
 * announced: an endpoint that answers about somebody else's token tells no anonymous caller anything.
 */
final readonly class AnnouncedIntrospection implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ClientAuthenticationMethodsInterface $methods,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $methods = array_values(array_filter(
            $this->methods->clientAuthenticationMethods(),
            static fn (ClientAuthenticationMethodInterface $method): bool => $method->authenticatesClient(),
        ));

        return [
            'introspection_endpoint' => $this->endpoints->locate($tenant)->introspection,
            'introspection_endpoint_auth_methods_supported' => MethodNames::of($methods),
            'introspection_endpoint_auth_signing_alg_values_supported' => $this->algorithms->assertionSigning($methods),
            'introspection_signing_alg_values_supported' => $this->algorithms->signing(),
        ];
    }
}
