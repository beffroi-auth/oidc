<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Port\ProvableMethodsInterface;

final readonly class ApprovalAuthenticationRequirement
{
    public function __construct(
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
    ) {
    }

    public function stepUpFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): ?StepUp
    {
        if (! $record->mayBeAnsweredBy($session->user)) {
            // A session that may not answer owes nothing: the record refuses it for who it is.
            return null;
        }
        $context = $this->of($record);

        return $context->stepUpFor($session, $context->isInQuestion() ? $this->credentials->findByUser($session->user) : []);
    }

    public function classFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): AuthenticationContextClass
    {
        return $this->of($record)->classFor($session);
    }

    private function of(BackchannelAuthenticationRecord $record): RequestedAuthenticationContext
    {
        return RequestedAuthenticationContext::against(
            $record->requestedAuthenticationContext(),
            $record->tenant,
            $this->provable->provableMethods($record->tenant),
        );
    }
}
