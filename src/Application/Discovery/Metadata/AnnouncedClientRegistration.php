<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3, RFC 7591 §3.1: where a client registers itself, announced for a tenant whose policy
 * registers clients and left out for one whose policy is closed, which is the default (decision 0009).
 *
 * It is derived from the policy and from nothing kept beside it: a tenant that announces this endpoint is
 * a tenant whose endpoint answers, and a tenant that does not is a tenant whose endpoint is not there.
 */
final readonly class AnnouncedClientRegistration implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ClientRegistrationPolicyInterface $policies,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        if ($this->policies->policyFor($tenant) === null) {
            return [];
        }

        return [
            'registration_endpoint' => $this->endpoints->locate($tenant)->clientRegistration,
        ];
    }
}
