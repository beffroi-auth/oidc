<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Administration;

use Beffroi\Oidc\Domain\Event\ConsentsReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\JournalReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;

/**
 * The acts an administrator writes in the journal of a person by reading them through the administration API
 * (decisions 0022 and 0038), which the page of the acts of that person lists unless the administrator is that person.
 */
final class ReadsByAnAdministrator
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        PersonReadByAnAdministrator::NAME,
        SessionsReadByAnAdministrator::NAME,
        JournalReadByAnAdministrator::NAME,
        MembershipReadByAnAdministrator::NAME,
        ConsentsReadByAnAdministrator::NAME,
    ];
}
