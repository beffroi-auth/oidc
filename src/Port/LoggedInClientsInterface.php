<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\Client;
use Symfony\Component\Uid\Uuid;

/**
 * The clients that hold a token issued in a session: a code a client never exchanged does not count.
 */
interface LoggedInClientsInterface
{
    /**
     * @return list<Client> each client once
     */
    public function ofSession(Uuid $session): array;
}
