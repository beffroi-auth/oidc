<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\ProvableMethodsInterface;
use function sprintf;

/**
 * What the authentication of an interaction still needs, at the two moments it is asked (architecture §4.3):
 * before any login, when only the request and the policy of the tenant are known, and once a session is in
 * hand, against what that session proved and what the user could still prove.
 *
 * The rules of the "acr" are the request's own (RequestedAuthenticationContext, decision 0010); what is here
 * is the reading they need, the methods the provider is wired to prove and the credentials of the user, plus
 * the rules of OIDC Core §3.1.2.1 that are not about a class: a forged hint, prompt=login, prompt=select_account
 * and max_age. A login done during this interaction satisfies all three of the last, whatever it proved.
 */
final readonly class AuthenticationRequirement
{
    public function __construct(
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
        private IdTokenHintVerifier $idTokenHints,
    ) {
    }

    /**
     * What the request demands of the authentication, established before a session is looked at: an essential
     * "acr" this provider can prove none of is refused here, and so is a hint whose signature is not ours.
     * Neither is something a user could do anything about on a page, so no page is shown for them
     * (OIDC Core §3.1.2.1, §5.5.1.1).
     *
     * @throws OAuth2Exception
     */
    public function beforeAnyLogin(AuthorizationRequest $request): RequestedAuthentication
    {
        $hinted = $request->idTokenHint === null ? null : $this->idTokenHints->verify($request->client, $request->idTokenHint);
        $context = RequestedAuthenticationContext::of($request, $this->provable->provableMethods($request->client->tenant));
        $context->assertTheProviderCanProveOne();

        return new RequestedAuthentication($context, $hinted);
    }

    /**
     * What the authentication of this interaction still needs against the session in hand, null when it needs
     * nothing.
     *
     * @throws OAuth2Exception
     */
    public function of(
        RequestedAuthentication $requested,
        Interaction $interaction,
        AuthenticationSession $session,
        DateTimeImmutable $now,
    ): ?RequiredLogin {
        $context = $requested->context;
        $stepUp = $context->stepUpFor($session, $context->isInQuestion() ? $this->credentials->findByUser($session->user) : []);
        $context->assertTheUserCouldMeetIt($session, $stepUp);
        $requirement = self::requirement($interaction, $session, $requested->hinted, $stepUp !== null, $now);
        if ($requirement === null) {
            return null;
        }

        return new RequiredLogin($requirement, $requirement === LoginRequirement::StrongerFactorRequired ? $stepUp : null);
    }

    /**
     * OIDC Core §3.1.2.1: a login done during this interaction satisfies prompt=login, max_age and a step-up,
     * whatever it proved; the step-up comes before prompt=login so that the page names what is missing when a
     * client sends both, as Symfony's re-authentication does.
     */
    private static function requirement(
        Interaction $interaction,
        AuthenticationSession $session,
        ?Subject $hinted,
        bool $stepUp,
        DateTimeImmutable $now,
    ): ?LoginRequirement {
        $request = $interaction->request;
        if ($hinted !== null && ! $session->user->subject->equals($hinted)) {
            return LoginRequirement::DifferentUser;
        }
        if ($session->authenticatedAt() >= $interaction->createdAt) {
            return null;
        }
        if ($stepUp) {
            return LoginRequirement::StrongerFactorRequired;
        }
        if ($request->hasPrompt(Prompt::Login)) {
            return LoginRequirement::ReauthenticationRequested;
        }
        if ($request->hasPrompt(Prompt::SelectAccount)) {
            return LoginRequirement::AccountSelectionRequested;
        }
        if ($request->maxAge !== null && $session->authenticatedAt()->modify(sprintf('+%d seconds', $request->maxAge)) < $now) {
            return LoginRequirement::MaxAgeExceeded;
        }

        return null;
    }
}
