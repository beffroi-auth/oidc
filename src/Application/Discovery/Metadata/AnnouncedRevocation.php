<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\MethodNames;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7009 §2, RFC 8414 §2
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
            'revocation_endpoint_auth_methods_supported' => MethodNames::of($methods),
            'revocation_endpoint_auth_signing_alg_values_supported' => $this->algorithms->assertionSigning($methods),
        ];
    }
}
