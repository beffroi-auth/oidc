<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function array_filter;
use function array_values;
use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\MethodNames;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7662 §2, RFC 9701 §7
 */
final readonly class AnnouncedIntrospection implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ClientAuthenticationMethodsInterface $methods,
        private AnnouncedAlgorithms $algorithms,
        private HeldSigningAlgorithms $held,
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
            'introspection_signing_alg_values_supported' => AlgorithmNames::of($this->held->defaultOf($tenant)),
        ];
    }
}
