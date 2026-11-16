<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Application\Administration\AdministrationAudience;
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

final readonly class AuthenticationRequirement
{
    private const string HINTS_NOBODY = 'The id_token_hint parameter names no end user of this client.';

    public function __construct(
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
        private IdTokenHintVerifier $idTokenHints,
        private PresentedSubjectReaderInterface $subjects,
        private AdministrationAudience $administration,
    ) {
    }

    /**
     * OIDC Core §3.1.2.1, §5.5.1.1, decision 0038
     *
     * @throws OAuth2Exception
     */
    public function beforeAnyLogin(AuthorizationRequest $request): RequestedAuthentication
    {
        $hinted = $this->hintedPerson($request);
        $context = RequestedAuthenticationContext::against(
            $this->administration->authenticationAskedBy($request),
            $request->client->tenant,
            $this->provable->provableMethods($request->client->tenant),
        );
        $context->assertTheProviderCanProveOne();

        return new RequestedAuthentication($context, $hinted);
    }

    /**
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
     * OIDC Core §3.1.2.1, §8
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

    private static function hintsAnotherUser(RequestedAuthentication $requested, AuthenticationSession $session): bool
    {
        return $requested->hinted !== null && ! $requested->hinted->id->equals($session->user->id);
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * The step-up precedes prompt=login so the page names what is missing; Symfony's re-authentication sends both.
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
