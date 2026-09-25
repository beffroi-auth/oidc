<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 8628 §4: where a client with no browser starts. The grant it goes with is announced by the fact of
 * being wired, as every other is (AnnouncedGrants), so this says the one thing RFC 8628 registers.
 */
final readonly class AnnouncedDeviceAuthorization implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'device_authorization_endpoint' => $this->endpoints->locate($tenant)->deviceAuthorization,
        ];
    }
}
