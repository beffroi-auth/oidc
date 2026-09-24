<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_any;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 8705 §3.3 and §5: whether the provider binds an access token to the certificate its client
 * presented, which is whether a method that proves one is wired and nothing else.
 */
final readonly class AnnouncedMutualTls implements MetadataContributorInterface
{
    public function __construct(
        private ClientAuthenticationMethodsInterface $methods,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $bound = array_any(
            $this->methods->clientAuthenticationMethods(),
            static fn (ClientAuthenticationMethodInterface $method): bool => $method instanceof CertificateBindingMethodInterface,
        );

        return [
            'tls_client_certificate_bound_access_tokens' => $bound,
        ];
    }
}
