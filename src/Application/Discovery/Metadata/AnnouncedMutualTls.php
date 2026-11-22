<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\CertificateBinding;
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
        return [
            'tls_client_certificate_bound_access_tokens' => CertificateBinding::servedBy($this->methods->clientAuthenticationMethods()),
        ];
    }
}
