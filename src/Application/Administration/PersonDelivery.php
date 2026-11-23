<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\PersonReadByAnAdministrator;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A person the administration API answers to an administrator, whether a read asked for them or a write that changed
 * nothing answers them as they are: an act of theirs that names the administrator (decisions 0022 and 0038).
 */
final readonly class PersonDelivery
{
    public function __construct(
        private EventDispatcherInterface $events,
    ) {
    }

    public function to(ActingAdministrator $administrator, User $user, RequestContext $context): void
    {
        $this->events->dispatch(new PersonReadByAnAdministrator(
            $context->receivedAt,
            $administrator->tenant,
            $administrator->clientId,
            $user->subject,
            $administrator->user->subject,
            $context,
        ));
    }
}
