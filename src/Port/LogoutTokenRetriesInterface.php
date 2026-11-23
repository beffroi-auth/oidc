<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * The issue of a logout token, tried again on the schedule of its delivery and given up with it.
 */
interface LogoutTokenRetriesInterface
{
    /**
     * @param Subject|null $administrator the administrator of the tenant who ended the session, whom the logout token names as the author of its act
     */
    public function issueLater(Client $client, AuthenticationSession $session, RequestContext $context, ?Subject $administrator = null): void;
}
