<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\MutualTlsEndpointLocatorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 8705 §5
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
