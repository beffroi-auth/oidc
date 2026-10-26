<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Exception\LoginRequiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use Beffroi\Oidc\Port\ProvableMethodsInterface;

/**
 * What the authentication of an interaction still needs, at the two moments it is asked (architecture §4.3):
 * before any login, when only the request and the policy of the tenant are known, and once a session is in
 * hand, against what that session proved and what the user could still prove.
 *
 * The rules of the "acr" are the request's own (RequestedAuthenticationContext, decision 0010); what is here
 * is the reading they need, the methods the provider is wired to prove and the credentials of the user, plus
 * the rules of OIDC Core §3.1.2.1 that are not about a class: a forged hint, a hint that names nobody or another
 * person than the one of the session, prompt=login, prompt=select_account and max_age. A login done during this
 * interaction satisfies all three of the last, whatever it proved.
 *
 * The "sub" of a hint is the one its client was given, so it is read back for that client (OIDC Core §8) and
 * never compared with the subject the core keeps: under a pairwise kind the two are never the same string.
 */
final readonly class AuthenticationRequirement
{
    private const string HINTS_NOBODY = 'The id_token_hint parameter names no end user of this client.';

    public function __construct(
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
        private IdTokenHintVerifier $idTokenHints,
        private PresentedSubjectReaderInterface $subjects,
    ) {
    }

    /**
     * What the request demands of the authentication, established before a session is looked at: an essential
     * "acr" this provider can prove none of is refused here, and so is a hint whose signature is not ours or that
     * names nobody. None is something a user could do anything about on a page, so no page is shown for them
     * (OIDC Core §3.1.2.1, §5.5.1.1).
     *
     * @throws OAuth2Exception
     */
    public function beforeAnyLogin(AuthorizationRequest $request): RequestedAuthentication
    {
        $hinted = $this->hintedPerson($request);
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
        $requirement = self::requirement($interaction, $session, self::hintsAnotherUser($requested, $session), $stepUp !== null, $now);
        if ($requirement === null) {
            return null;
        }

        return new RequiredLogin($requirement, $requirement === LoginRequirement::StrongerFactorRequired ? $stepUp : null);
    }

    /**
     * OIDC Core §3.1.2.1 id_token_hint: the person the hint names, its "sub" read back for the client of the request.
     * A "sub" that names nobody for that client, as the one a client was given does once it registers another kind of
     * subject (§8), is met by no login, so the client is answered login_required (§3.1.2.6).
     *
     * @throws OAuth2Exception
     */
    private function hintedPerson(AuthorizationRequest $request): ?User
    {
        if ($request->idTokenHint === null) {
            return null;
        }
        $subject = $this->idTokenHints->verify($request->client, $request->idTokenHint);

        return $this->subjects->findUser($request->client, $subject) ?? throw new LoginRequiredException(self::HINTS_NOBODY);
    }

    /**
     * OIDC Core §3.1.2.1 id_token_hint: the hint names somebody other than the user of the session.
     */
    private static function hintsAnotherUser(RequestedAuthentication $requested, AuthenticationSession $session): bool
    {
        return $requested->hinted !== null && ! $requested->hinted->id->equals($session->user->id);
    }

    /**
     * OIDC Core §3.1.2.1: a login done during this interaction satisfies prompt=login, max_age and a step-up,
     * whatever it proved; the step-up comes before prompt=login so that the page names what is missing when a
     * client sends both, as Symfony's re-authentication does.
     */
    private static function requirement(
        Interaction $interaction,
        AuthenticationSession $session,
        bool $anotherUserHinted,
        bool $stepUp,
        DateTimeImmutable $now,
    ): ?LoginRequirement {
        $request = $interaction->request;
        if ($anotherUserHinted) {
            return LoginRequirement::DifferentUser;
        }
        if ($interaction->sawTheLoginOf($session)) {
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
        if ($request->maxAgeExceededBy($session, $now)) {
            return LoginRequirement::MaxAgeExceeded;
        }

        return null;
    }
}
