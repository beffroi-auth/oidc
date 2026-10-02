<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

/**
 * The two ways a provider tells a client that a session ended, each one a specification of its own: the
 * closed set those two specifications fix. Which of them a deployment serves is what it wires, never
 * what this enumeration lists (issue #98).
 */
enum LogoutChannel: string
{
    /**
     * Back-Channel Logout 1.0: a logout token posted to the client by the provider itself.
     */
    case BackChannel = 'back_channel';

    /**
     * Front-Channel Logout 1.0: the client's URI loaded in a frame by the browser of the user.
     */
    case FrontChannel = 'front_channel';
}
