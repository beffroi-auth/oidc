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

/**
 * The logout token posted to a client of a session that ended (Back-Channel Logout 1.0 §2.4), signed by
 * the active key of the tenant and verified by the client on the JWK Set, like every other JWS of the
 * provider. It is issued only where the integration wires something that posts one: a deployment that
 * tells its clients nothing, or tells them through the front channel alone, signs no such token. What it
 * declares is how long the delivery of such a token may still be tried, read from what delivers it so
 * that the two cannot disagree, which is the rule issue #155 asks of every kind. It is the same interval the
 * "exp" of the token is set from (`LogoutTokenIssuer`), so the key lives exactly as long as a token
 * signed by it may be accepted.
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
