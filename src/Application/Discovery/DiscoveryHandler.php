<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Discovery\ProviderMetadata;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use function array_key_exists;
use function sprintf;

/**
 * OIDC Discovery §3, RFC 8414 §2
 */
final readonly class DiscoveryHandler
{
    /**
     * @param iterable<MetadataContributorInterface> $contributors in the order the document publishes them
     * @param int $maxAge in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public function __construct(
        private iterable $contributors,
        private int $maxAge = 3600,
    ) {
        ProviderMetadata::assertCacheLifetime($maxAge);
    }

    /**
     * @throws InvalidArgumentException when a capability refuses its wiring or two claim the same member
     */
    public function handle(Tenant $tenant): ProviderMetadata
    {
        $members = [];
        foreach ($this->contributors as $contributor) {
            foreach ($contributor->metadata($tenant) as $member => $value) {
                if (array_key_exists($member, $members)) {
                    throw new InvalidArgumentException(sprintf('Two capabilities of this provider both announce "%s".', $member));
                }
                $members[$member] = $value;
            }
        }

        return new ProviderMetadata($tenant->issuer, $members, $this->maxAge);
    }
}
