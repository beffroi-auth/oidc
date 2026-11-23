<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonDisabling;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Beffroi\Oidc\Exception\OwnAccountRefusedException;
use Symfony\Component\Uid\Uuid;

/**
 * A person of the tenant disabled by an administrator through the administration API (decision 0038), on the use case
 * `beffroi:user:disable` calls: the act and the end of each session of theirs name the administrator. A person disabled
 * already is answered as they are, which is a read of them (decision 0022). The answer delivers the person, so it spends
 * one person of the budget of the administrator first (decision 0014).
 */
final readonly class AdministeredDisabling
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PersonDisabling $disabling,
        private PersonDelivery $delivery,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws OwnAccountRefusedException when the person is the administrator
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return User|null the person as they now are, null when the tenant has no person of that identifier
     */
    public function disable(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?User
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        if ($user->id->equals($administrator->user->id)) {
            throw new OwnAccountRefusedException('An administrator does not disable the account they act with.');
        }
        $this->delivered->spend($administrator, 1, $context);
        if ($this->disabling->disableByAnAdministrator($user, $administrator->user->subject, $context) === null) {
            $this->delivery->to($administrator, $user, $context);
        }

        return $user;
    }
}
