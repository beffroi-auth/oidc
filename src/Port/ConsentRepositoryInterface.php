<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;

interface ConsentRepositoryInterface
{
    public function findActive(User $user, Client $client): ?Consent;

    public function save(Consent $consent): void;
}
