<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonEnabling;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Symfony\Component\Uid\Uuid;

/**
 * A person of the tenant enabled again by an administrator through the administration API (decision 0038), on the use
 * case `beffroi:user:enable` calls: the act names the administrator. A person enabled already is answered as they are,
 * which is a read of them (decision 0022). The answer delivers the person, so it spends one person of the budget of the
 * administrator first (decision 0014).
 */
final readonly class AdministeredEnabling
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PersonEnabling $enabling,
        private PersonDelivery $delivery,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return User|null the person as they now are, null when the tenant has no person of that identifier
     */
    public function enable(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?User
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user !== null) {
            $this->delivered->spend($administrator, 1, $context);
            if (! $this->enabling->enableByAnAdministrator($user, $administrator->user->subject, $context)) {
                $this->delivery->to($administrator, $user, $context);
            }
        }

        return $user;
    }
}
