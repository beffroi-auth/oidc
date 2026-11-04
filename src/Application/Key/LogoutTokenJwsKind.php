<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Key;

use DateInterval;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeyBoundArtifactInterface;
use Beffroi\Oidc\Domain\EndSession\LogoutChannel;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Beffroi\Oidc\Port\ServedLogoutChannelsInterface;
use function in_array;

final readonly class LogoutTokenJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private LogoutTokenDeliveryInterface $delivery,
        private ServedLogoutChannelsInterface $channels,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return in_array(LogoutChannel::BackChannel, $this->channels->servedLogoutChannels(), true)
            ? $this->delivery->deliveryBudget()
            : null;
    }
}
