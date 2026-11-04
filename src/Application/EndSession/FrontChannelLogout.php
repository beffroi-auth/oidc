<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Beffroi\Oidc\Port\LoggedInClientsInterface;

/**
 * Front-Channel Logout 1.0 §2, §3
 */
final readonly class FrontChannelLogout
{
    public function __construct(
        private LoggedInClientsInterface $clients,
    ) {
    }

    /**
     * @param list<AuthenticationSession> $sessions
     */
    public function pageFor(array $sessions, ?string $continueTo): ?FrontChannelLogoutPage
    {
        $frames = [];
        foreach ($sessions as $session) {
            foreach ($this->clients->ofSession($session->id) as $client) {
                if ($client->registration->frontChannelLogoutUri === null) {
                    continue;
                }
                $frames[] = FrontChannelLogoutFrame::ofSession($client, $session);
            }
        }

        return $frames === [] ? null : new FrontChannelLogoutPage($frames, $continueTo);
    }
}
