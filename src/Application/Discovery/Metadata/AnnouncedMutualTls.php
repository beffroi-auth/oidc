<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function array_any;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 8705 §3.3, §5
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
