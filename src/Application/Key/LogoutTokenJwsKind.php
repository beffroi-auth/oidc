<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Key\KeyUse;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\KeyBoundArtifactInterface;
use Heidi\Oidc\Domain\EndSession\LogoutChannel;
use Heidi\Oidc\Port\LogoutTokenDeliveryInterface;
use Heidi\Oidc\Port\ServedLogoutChannelsInterface;
use function in_array;

/**
 * The logout token posted to a client of a session that ended (Back-Channel Logout 1.0 §2.4), signed by
 * the active key of the tenant and verified by the client on the JWK Set, like every other JWS of the
 * provider. It is issued only where the integration wires something that posts one: a deployment that
 * tells its clients nothing, or tells them through the front channel alone, signs no such token. Having
 * no "exp" of its own, what it declares is how long its delivery may still be tried, read from what
 * delivers it so that the two cannot disagree, which is the rule issue #155 asks of every kind.
 */
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
