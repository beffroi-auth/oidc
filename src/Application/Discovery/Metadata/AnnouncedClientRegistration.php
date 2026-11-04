<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3, RFC 7591 §3.1
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
