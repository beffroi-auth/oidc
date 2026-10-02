<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutFrame;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Beffroi\Oidc\Port\LoggedInClientsInterface;

/**
 * Front-Channel Logout 1.0 §2 and §3: once a session has ended, the browser that holds the cookies of
 * its clients is given a page that loads one frame per client that registered a front-channel logout
 * URI. The clients are the ones the session signed in, read where the back channel reads them
 * (architecture §4.9), so that the two channels tell the same clients; a client that registered no URI
 * gets no frame, and a session that signed nobody in gets no page.
 */
final readonly class FrontChannelLogout
{
    public function __construct(
        private LoggedInClientsInterface $clients,
    ) {
    }

    /**
     * @param string|null $continueTo where the browser goes once the frames are done (RP-Initiated
     *                                Logout §3), null when the request named nowhere to go back to
     *
     * @return FrontChannelLogoutPage|null null when no client of the session is loaded by the page
     */
    public function pageFor(AuthenticationSession $session, ?string $continueTo): ?FrontChannelLogoutPage
    {
        $frames = [];
        foreach ($this->clients->ofSession($session->id) as $client) {
            if ($client->registration->frontChannelLogoutUri === null) {
                continue;
            }
            $frames[] = FrontChannelLogoutFrame::ofSession($client, $session);
        }

        return $frames === [] ? null : new FrontChannelLogoutPage($frames, $continueTo);
    }
}
