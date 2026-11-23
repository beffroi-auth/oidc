<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonEnabling;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * A person of the tenant enabled again by an administrator through the administration API (decision 0038), on the use
 * case `beffroi:user:enable` calls: the act names the administrator. A person enabled already is answered as they are,
 * which is a read of them (decision 0022).
 */
final readonly class AdministeredEnabling
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PersonEnabling $enabling,
        private PersonDelivery $delivery,
    ) {
    }

    /**
     * @return User|null the person as they now are, null when the tenant has no person of that identifier
     */
    public function enable(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?User
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user !== null && ! $this->enabling->enableByAnAdministrator($user, $administrator->user->subject, $context)) {
            $this->delivery->to($administrator, $user, $context);
        }

        return $user;
    }
}
