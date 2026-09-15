<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;

interface ConsentRepositoryInterface
{
    /**
     * The consent in force between a user and a client, if any: at most one is active at a time, a new
     * grant superseding the previous one (architecture §4.3).
     */
    public function findActive(User $user, Client $client): ?Consent;

    public function save(Consent $consent): void;
}
