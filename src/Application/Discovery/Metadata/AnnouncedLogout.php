<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function in_array;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\EndSession\LogoutChannel;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;

/**
 * RP-Initiated Logout §2.1, Back-Channel Logout 1.0 §3 and Front-Channel Logout 1.0 §3: where a client
 * sends a user to sign out, and which channels the integration wired. A channel that is served always
 * carries the session, so what announces one announces the other.
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
