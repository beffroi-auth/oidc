<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRequirementInterface;

/**
 * RFC 9126 §5: where a request is pushed, and whether pushing it is the only way in, which is what every
 * client registered here requires and not a switch of the deployment (§6).
 */
final readonly class AnnouncedPushedAuthorization implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private PushedAuthorizationRequirementInterface $requirement,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'pushed_authorization_request_endpoint' => $this->endpoints->locate($tenant)->pushedAuthorizationRequest,
            'require_pushed_authorization_requests' => $this->requirement->requiresPushedAuthorizationRequests($tenant),
        ];
    }
}
