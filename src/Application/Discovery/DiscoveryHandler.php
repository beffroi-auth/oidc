<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\MetadataContributorInterface;
use function array_key_exists;
use function sprintf;

/**
 * Serves the document of a tenant (OIDC Discovery §3, RFC 8414 §2): it asks each capability the
 * deployment is wired with what it puts in the document, in the order they are wired, and hands back
 * what they said.
 *
 * It knows no member. A capability that arrives brings its own contributor and a line in the wiring,
 * and nothing here changes.
 */
final readonly class DiscoveryHandler
{
    /**
     * @param iterable<MetadataContributorInterface> $contributors in the order the document publishes them
     * @param int $maxAge how long a client may keep the document, in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds: a deployment learns
     *                                  it at boot rather than on the first request
     */
    public function __construct(
        private iterable $contributors,
        private int $maxAge = 3600,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
    }

    /**
     * @throws InvalidArgumentException when two capabilities claim the same member: which of the two the
     *                                  document would carry is not something a deployment should have to
     *                                  guess, and a client reading it would never know
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
