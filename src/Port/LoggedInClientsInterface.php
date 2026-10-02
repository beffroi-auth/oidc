<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\Client;
use Symfony\Component\Uid\Uuid;

/**
 * The clients a session signed in, that is the relying parties that hold a token issued in it
 * (Back-Channel Logout 1.0 §2.6). A companion of the grant store, where every token of a session leaves
 * its trace (architecture §4.4): a code a client never exchanged gave it no session and is not one.
 */
interface LoggedInClientsInterface
{
    /**
     * @return list<Client> each client once, whatever the number of grants; a client no longer registered is not listed
     */
    public function ofSession(Uuid $session): array;
}
