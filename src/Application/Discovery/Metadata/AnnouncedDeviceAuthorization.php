<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 8628 §4
 */
final readonly class AnnouncedDeviceAuthorization implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        if ($this->grants->askingTheUserOnAnotherDevice() === []) {
            return [];
        }

        return [
            'device_authorization_endpoint' => $this->endpoints->locate($tenant)->deviceAuthorization,
        ];
    }
}
