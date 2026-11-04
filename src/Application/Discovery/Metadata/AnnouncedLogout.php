<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function in_array;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;

/**
 * RP-Initiated Logout §2.1, Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3
 */
final readonly class AnnouncedLogout implements MetadataContributorInterface
{
    public function __construct(
        private EndpointLocatorInterface $endpoints,
        private ServedLogoutChannelsInterface $channels,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $served = $this->channels->servedLogoutChannels();

        return [
            'end_session_endpoint' => $this->endpoints->locate($tenant)->endSession,
            'backchannel_logout_supported' => in_array(LogoutChannel::BackChannel, $served, true),
            'backchannel_logout_session_supported' => in_array(LogoutChannel::BackChannel, $served, true),
            'frontchannel_logout_supported' => in_array(LogoutChannel::FrontChannel, $served, true),
            'frontchannel_logout_session_supported' => in_array(LogoutChannel::FrontChannel, $served, true),
        ];
    }
}
