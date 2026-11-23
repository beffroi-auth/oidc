<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\LoggedInClientsInterface;
use Beffroi\Oidc\Port\LogoutTokenRetriesInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Back-Channel Logout 1.0 §2.6
 */
final readonly class BackChannelLogout
{
    public function __construct(
        private LoggedInClientsInterface $clients,
        private LogoutTokenIssuer $tokens,
        private LogoutTokenRetriesInterface $retries,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function sessionEnded(AuthenticationSession $session, RequestContext $context): void
    {
        $later = [];
        foreach ($this->clients->ofSession($session->id) as $client) {
            try {
                $this->tell($client, $session, $context);
            } catch (ClientKeysUnavailableException) {
                $later[] = $client;
            }
        }
        // After the loop: a failure in it has the end of the session handled again, which would leave a client twice.
        foreach ($later as $client) {
            $this->retries->issueLater($client, $session, $context);
        }
    }

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws ClientKeysUnavailableException when the client encrypts its ID tokens and publishes no key that can be read for it, or one that receives no JWE
     */
    public function tell(Client $client, AuthenticationSession $session, RequestContext $context): void
    {
        $logoutUri = $client->registration->backChannelLogoutUri;
        if ($logoutUri === null) {
            return;
        }
        $now = $this->clock->now();
        $this->events->dispatch(new LogoutTokenIssued(
            $now,
            $client->tenant,
            $client->registration->clientId,
            $session->user->subject,
            $logoutUri,
            $session->id,
            $this->tokens->issue($client, $session, $now),
            $context,
        ));
    }
}
