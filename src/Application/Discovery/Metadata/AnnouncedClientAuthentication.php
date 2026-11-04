<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\MethodNames;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3
 */
final readonly class AnnouncedClientAuthentication implements MetadataContributorInterface
{
    public function __construct(
        private ClientAuthenticationMethodsInterface $methods,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $methods = $this->methods->clientAuthenticationMethods();

        return [
            'token_endpoint_auth_methods_supported' => MethodNames::of($methods),
            'token_endpoint_auth_signing_alg_values_supported' => $this->algorithms->assertionSigning($methods),
        ];
    }
}
