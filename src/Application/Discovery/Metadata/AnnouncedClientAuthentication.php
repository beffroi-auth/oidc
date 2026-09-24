<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3: how a client authenticates at the token endpoint, which is the methods wired into
 * the authenticator in the order it tries them, and what an assertion of those methods may be signed
 * with. Nothing here enumerates a method.
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
            'token_endpoint_auth_methods_supported' => array_map(
                static fn (ClientAuthenticationMethodInterface $method): string => $method->name(),
                $methods,
            ),
            'token_endpoint_auth_signing_alg_values_supported' => $this->algorithms->assertionSigning($methods),
        ];
    }
}
