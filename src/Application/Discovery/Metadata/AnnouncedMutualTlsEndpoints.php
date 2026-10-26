<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 8705 §5: where a client reaches the endpoints that ask for a certificate, when the deployment
 * serves them on a host of their own. One that has no such host announces no aliases at all, rather than
 * aliases that point back at the ordinary endpoints.
 *
 * An alias names an endpoint the document announces: the device authorization endpoint has one only when
 * a grant whose user is asked on another device is wired, as it is announced only then
 * (AnnouncedDeviceAuthorization).
 */
final readonly class AnnouncedMutualTlsEndpoints implements MetadataContributorInterface
{
    public function __construct(
        private MutualTlsEndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $endpoints = $this->endpoints->locateMutualTls($tenant);
        if ($endpoints === null) {
            return [];
        }

        $aliases = [
            'token_endpoint' => $endpoints->token,
            'userinfo_endpoint' => $endpoints->userinfo,
            'introspection_endpoint' => $endpoints->introspection,
            'revocation_endpoint' => $endpoints->revocation,
            'pushed_authorization_request_endpoint' => $endpoints->pushedAuthorizationRequest,
        ];
        if ($this->grants->askingTheUserOnAnotherDevice() !== []) {
            $aliases['device_authorization_endpoint'] = $endpoints->deviceAuthorization;
        }

        return [
            'mtls_endpoint_aliases' => $aliases,
        ];
    }
}
