<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;

/**
 * OIDC Discovery §3 and RFC 9101 §10.5: both ways in are served, and a "request_uri" is read back only
 * from a URL its client registered, which decision 0006 makes a rule and not an option. The algorithms
 * are the ones the provider verifies signatures with; "none" stands beside them only when a client of
 * the tenant registered it.
 *
 * What the member says is what a client of this tenant may register and be read under, and never what any
 * client is read under: the grant is carried by a client and by neither the tenant nor a global setting
 * (decision 0012), so "none" among the values means one client of the tenant registered it, not that an
 * unsigned object is read from whoever publishes one. A client that registered nothing is read under any
 * of the wired algorithms and never unsigned (AnyRegisteredAlgorithm), so a caller that reads the member
 * as a promise made to itself is refused, which is what one module of the Dynamic OP plan does
 * (oidcc-request-uri-unsigned, issue #385, the "known" list of CONFORMANCE_PLANS).
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
