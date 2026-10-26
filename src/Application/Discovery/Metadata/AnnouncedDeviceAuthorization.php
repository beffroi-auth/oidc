<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 8628 §4: where a client with no browser starts. The grant it goes with is announced by the fact of
 * being wired, as every other is (AnnouncedGrants), so this says the one thing RFC 8628 registers.
 *
 * A provider wired with no grant whose user is asked on another device announces no such endpoint, rather
 * than one that refuses every client (DeviceAuthorizationHandler).
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
