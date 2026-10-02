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

/**
 * What a backchannel authentication request asks of the authentication of the user who answers it (CIBA
 * Core §7.1, decision 0010): the counterpart of AuthenticationRequirement at the endpoint a browser
 * reaches, for the one flow whose user is asked on a page of their own (architecture §4.14).
 *
 * The rules are the request's own (RequestedAuthenticationContext); what is here is the reading they
 * need, the methods the provider is wired to prove and the credentials of the user. It is asked at one
 * moment and not at three: there is no login to require of somebody who is already signed in on the page
 * where they answer, and no refusal to send back before any page, §7.1 taking "acr_values" and taking no
 * "claims", which leaves this flow with no essential form of the demand at all. What is left of the
 * policy is the step-up, and the class the tokens will name.
 */
final readonly class ApprovalAuthenticationRequirement
{
    public function __construct(
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
    ) {
    }

    /**
     * Decision 0010: the client asked for classes this provider can prove, the session the user holds
     * satisfies none and a credential of theirs would, so one more proof is asked for before the approval
     * is recorded. Null when nothing is asked, when the session already satisfies, and when no credential
     * of the user could: a voluntary demand is never refused (OIDC Core §5.5.1.1), and a request nobody
     * could satisfy is approved with the class the session has, which is what the tokens will say.
     */
    public function stepUpFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): ?StepUp
    {
        if (! $record->mayBeAnsweredBy($session->user)) {
            // a session that may not answer this request owes it nothing: the record refuses it for who
            // it is, before anything is asked of what it proves (§7.1)
            return null;
        }
        $context = $this->of($record);

        return $context->stepUpFor($session, $context->isInQuestion() ? $this->credentials->findByUser($session->user) : []);
    }

    /**
     * The class every token descending from this approval will name (OIDC Core §2): the requested one the
     * session satisfies, and the one the session has when the request asked for none it satisfies.
     */
    public function classFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): AuthenticationContextClass
    {
        return $this->of($record)->classFor($session);
    }

    /**
     * What the request asks, judged against the policy of its tenant and against what this provider is
     * wired to prove.
     */
    private function of(BackchannelAuthenticationRecord $record): RequestedAuthenticationContext
    {
        return RequestedAuthenticationContext::against(
            $record->requestedAuthenticationContext(),
            $record->tenant,
            $this->provable->provableMethods(),
        );
    }
}
