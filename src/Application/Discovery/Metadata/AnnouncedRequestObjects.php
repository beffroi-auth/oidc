<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * OIDC Discovery §3, RFC 9101 §10.5
 *
 * "none" is announced when one client of the tenant registered it; a client that did not is never read unsigned.
 */
final readonly class AnnouncedRequestObjects implements MetadataContributorInterface
{
    public function __construct(
        private UnsignedRequestObjectsInterface $unsigned,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $signing = $this->algorithms->signing();

        return [
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => true,
            'request_object_signing_alg_values_supported' => $this->unsigned->acceptsUnsignedRequestObjects($tenant)
                ? [...$signing, UnsignedRequestObjects::ALGORITHM]
                : $signing,
            ...$this->algorithms->encryptionOf('request_object_encryption'),
        ];
    }
}
