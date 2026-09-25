<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use Heidi\Oidc\Port\LoggedInClientsInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Back-Channel Logout 1.0 §2.6: a session that ended is announced to every client it signed in that
 * registered a back-channel logout URI, once each, whatever ended it (the user, a relying party, an
 * administrator, the expiry) since the announcement is made on the end and not on the request that
 * asked for it. Minting is here, delivery is not (architecture §5.6): a client that cannot be reached
 * must not hold a logout back, and a retry must not ask the KMS to sign again.
 */
final readonly class BackChannelLogout
{
    public function __construct(
        private LoggedInClientsInterface $clients,
        private LogoutTokenIssuer $tokens,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    public function sessionEnded(AuthenticationSession $session, RequestContext $context): void
    {
        $now = $this->clock->now();
        foreach ($this->clients->ofSession($session->id) as $client) {
            $logoutUri = $client->registration->backChannelLogoutUri;
            if ($logoutUri === null) {
                continue;
            }
            $this->events->dispatch(new LogoutTokenIssued(
                $now,
                $client->tenant,
                $client->registration->clientId,
                $logoutUri,
                $session->id,
                $this->tokens->issue($client, $session, $now),
                $context,
            ));
        }
    }
}
