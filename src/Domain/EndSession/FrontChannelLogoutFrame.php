<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\LogicException;
use function sprintf;

/**
 * One client of an ended session, as the logout page loads it (Front-Channel Logout 1.0 §2): the URI it
 * registered, with "iss" and "sid" added when it declared that it reads them, and never otherwise, since
 * §2 makes the two parameters conditional on frontchannel_logout_session_required. The origin is kept
 * beside the URI because that is what the policy of the page names (RFC 6454 §3.2).
 */
final readonly class FrontChannelLogoutFrame
{
    private function __construct(
        public string $clientId,
        public string $uri,
        public string $origin,
    ) {
    }

    /**
     * @throws LogicException for a client that registered no front-channel logout URI, which the caller
     *                        leaves out of the page rather than asking for
     */
    public static function ofSession(Client $client, AuthenticationSession $session): self
    {
        $registered = $client->frontChannelLogoutUri ?? throw new LogicException(sprintf('The client "%s" registered no front-channel logout URI and is not loaded by the logout page.', $client->clientId));
        $uri = $client->frontChannelLogoutSessionRequired ? $registered->withParameters([
            'iss' => (string) $session->tenant->issuer,
            'sid' => $session->id->toRfc4122(),
        ]) : $registered->value;

        return new self($client->clientId, $uri, $registered->origin);
    }
}
