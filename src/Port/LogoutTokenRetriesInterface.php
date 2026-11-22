<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * The issue of a logout token, tried again on the schedule of its delivery and given up with it.
 */
interface LogoutTokenRetriesInterface
{
    public function issueLater(Client $client, AuthenticationSession $session, RequestContext $context): void;
}
