<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Symfony\Component\Uid\Uuid;

/**
 * A credential of a person of the tenant, revoked by an administrator through the administration API on the use case
 * `beffroi:user:revoke-credential` calls (decision 0038): it never authenticates again, the sessions it opened stay
 * open, and the act of its revocation names the administrator. One revoked already is left as it is and answered, which
 * is a read of the person (decision 0022) and spends one person of the budget of the administrator (decision 0014).
 */
final readonly class AdministeredCredentialRevocation
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private CredentialRepositoryInterface $credentials,
        private CredentialRevocation $revocation,
        private PersonDelivery $delivery,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the credential was revoked already and the budget of the administrator has no person left
     *
     * @return (Credential&RevocableCredentialInterface)|null the credential revoked, null when the tenant has no person of that identifier or the person no credential of that identifier a revocation applies to
     */
    public function revoke(
        ActingAdministrator $administrator,
        Uuid $person,
        Uuid $credential,
        RequestContext $context,
    ): (Credential&RevocableCredentialInterface)|null {
        $user = $this->persons->find($administrator->tenant, $person);
        $held = $user === null ? null : $this->credentials->find($credential);
        if ($user === null || ! $held instanceof RevocableCredentialInterface || ! $held->user->id->equals($user->id)) {
            return null;
        }
        if ($held->isRevoked()) {
            $this->delivered->spend($administrator, 1, $context);
            $this->delivery->to($administrator, $user, $context);
        } else {
            $this->revocation->revokeByAnAdministrator($held, $administrator->user->subject, $context);
        }

        return $held;
    }
}
