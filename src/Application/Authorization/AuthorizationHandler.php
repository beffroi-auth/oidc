<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\AuthorizationResponse;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;
use Heidi\Oidc\Domain\Interaction\ConsentRequirement;
use Heidi\Oidc\Domain\Interaction\Granted;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Domain\Interaction\LoginRequirement;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\ConsentRequiredException;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\LoginRequiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnmetAuthenticationRequirementsException;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decides what a validated authorization request still needs (architecture §4.3): a login, a consent, or
 * nothing, in which case the code is issued. begin() parks the request in an Interaction; resume(),
 * grantConsent() and deny() apply the same rules at every step. With prompt=none a needed page is the
 * redirected error login_required or consent_required (OIDC Core §3.1.2.6).
 */
final readonly class AuthorizationHandler
{
    private const string LOGIN_REQUIRED = 'The end user is not authenticated as the request demands and prompt=none forbids asking.';

    private const string CONSENT_REQUIRED = 'No consent covers the request and prompt=none forbids asking.';

    private const string ACCESS_DENIED = 'The end user denied the request.';

    private const string UNMET_AUTHENTICATION_REQUIREMENTS = 'No requested acr value is one this provider can assert, see acr_values_supported.';

    public function __construct(
        private InteractionRepositoryInterface $interactions,
        private ConsentRepositoryInterface $consents,
        private AuthorizationCodeRepositoryInterface $codes,
        private IdTokenHintVerifier $idTokenHints,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private DateInterval $interactionLifetime = new DateInterval('PT10M'),
        private DateInterval $codeLifetime = new DateInterval('PT60S'),
    ) {
    }

    /**
     * @param string|null $locale the language of the pages of this interaction
     *
     * @throws OAuth2Exception redirectable, the interaction being completed
     */
    public function begin(AuthorizationRequest $request, ?AuthenticationSession $session, RequestContext $context, ?string $locale = null): AuthorizationDecision
    {
        $now = $this->clock->now();
        $interaction = new Interaction(Interaction::generateId(), $request->client->tenant, $request, $locale, $now, $now->add($this->interactionLifetime));

        return $this->decide($interaction, $session, $context, $now);
    }

    /**
     * After the login page.
     *
     * @throws InteractionCompletedException
     * @throws InteractionExpiredException
     * @throws OAuth2Exception
     */
    public function resume(Interaction $interaction, ?AuthenticationSession $session, RequestContext $context): AuthorizationDecision
    {
        $now = $this->clock->now();
        $interaction->assertResumable($now);

        return $this->decide($interaction, $session, $context, $now);
    }

    /**
     * After the consent page, when the user agreed: the scopes of the request are added to the consent in force.
     *
     * @throws InteractionCompletedException
     * @throws InteractionExpiredException
     * @throws OAuth2Exception
     */
    public function grantConsent(Interaction $interaction, AuthenticationSession $session, RequestContext $context): AuthorizationDecision
    {
        $now = $this->clock->now();
        $interaction->assertResumable($now);
        if (! $session->isActive($now)) {
            return $this->decide($interaction, null, $context, $now);
        }
        $interaction->authenticate($session, $now);

        $client = $interaction->request->client;
        $previous = $this->consents->findActive($session->user, $client);
        if ($previous === null) {
            $consent = new Consent(Uuid::v7(), $session->user, $client, $interaction->request->scopes, $now);
        } else {
            $consent = $previous->extendedWith($interaction->request->scopes, Uuid::v7(), $now);
            $this->consents->save($previous);
        }
        $this->consents->save($consent);
        $this->events->dispatch(new ConsentGranted($consent, $previous, $context));
        $interaction->consent($consent, $now);

        return $this->decide($interaction, $session, $context, $now);
    }

    /**
     * After the consent page, when the user refused (RFC 6749 §4.1.2.1).
     *
     * @throws InteractionCompletedException
     * @throws InteractionExpiredException
     * @throws AccessDeniedException always
     */
    public function deny(Interaction $interaction): never
    {
        $interaction->complete($this->clock->now());
        $this->interactions->save($interaction);

        throw new AccessDeniedException(self::ACCESS_DENIED);
    }

    /**
     * @throws OAuth2Exception
     */
    private function decide(Interaction $interaction, ?AuthenticationSession $session, RequestContext $context, DateTimeImmutable $now): AuthorizationDecision
    {
        $request = $interaction->request;
        $requestedClasses = AuthenticationContextRequest::of($request);
        try {
            // before anything else: a forged hint is refused without a login
            $hinted = $request->idTokenHint === null ? null : $this->idTokenHints->verify($request->client, $request->idTokenHint);
            $this->assertCanBeMet($requestedClasses);
            if ($session === null || ! $session->isActive($now)) {
                return $this->loginRequired($interaction, LoginRequirement::NoSession);
            }
            $loginRequirement = $this->loginRequirement($interaction, $session, $hinted, $now);
            if ($loginRequirement !== null) {
                return $this->loginRequired($interaction, $loginRequirement);
            }
            $interaction->authenticate($session, $now);

            $consentRequirement = $this->consentRequirement($interaction, $session, $now);
            if ($consentRequirement !== null) {
                if ($request->hasPrompt(Prompt::None)) {
                    throw new ConsentRequiredException(self::CONSENT_REQUIRED);
                }
                $this->interactions->save($interaction);

                return new ConsentRequired($interaction, $session, $request->scopes, $consentRequirement);
            }
        } catch (OAuth2Exception $exception) {
            $interaction->complete($now);
            $this->interactions->save($interaction);

            throw $exception;
        }

        $code = AuthorizationCode::generate();
        $record = new AuthorizationCode(
            AuthorizationCode::hash($code),
            Uuid::v7(),
            $request->client,
            $session,
            $request->redirectUri,
            $request->scopes,
            $request->nonce,
            $request->codeChallenge,
            $request->claims,
            AuthenticationSnapshot::ofSession($session, $requestedClasses->firstSatisfiedBy($session) ?? $session->authenticationContextClass()),
            $now,
            $now->add($this->codeLifetime),
        );
        $this->codes->save($record);
        $interaction->complete($now);
        $this->interactions->save($interaction);
        $this->events->dispatch(new AuthorizationCodeIssued($record, $context));

        return new Granted($interaction, $record, new AuthorizationResponse($request->client->tenant->issuer, $request->redirectUri, $request->state, $code));
    }

    /**
     * @throws LoginRequiredException when prompt=none forbids the login page
     */
    private function loginRequired(Interaction $interaction, LoginRequirement $requirement): LoginRequired
    {
        if ($interaction->request->hasPrompt(Prompt::None)) {
            throw new LoginRequiredException(self::LOGIN_REQUIRED);
        }
        $this->interactions->save($interaction);

        return new LoginRequired($interaction, $requirement);
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" naming only classes the provider cannot assert fails without a
     * login; a voluntary one is never refused.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    private function assertCanBeMet(AuthenticationContextRequest $requested): void
    {
        if ($requested->essential && ! $requested->namesNoClass() && ! $requested->canBeMetWith(AuthenticationContextClass::supported())) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AUTHENTICATION_REQUIREMENTS);
        }
    }

    /**
     * OIDC Core §3.1.2.1: a login done during this interaction satisfies prompt=login and max_age.
     */
    private function loginRequirement(Interaction $interaction, AuthenticationSession $session, ?Subject $hinted, DateTimeImmutable $now): ?LoginRequirement
    {
        $request = $interaction->request;
        if ($hinted !== null && ! $session->user->subject->equals($hinted)) {
            return LoginRequirement::DifferentUser;
        }
        if ($session->authenticatedAt() >= $interaction->createdAt) {
            return null;
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

    /**
     * Architecture §4.3: prompt=consent asks again unless the consent was given during this interaction.
     */
    private function consentRequirement(Interaction $interaction, AuthenticationSession $session, DateTimeImmutable $now): ?ConsentRequirement
    {
        $request = $interaction->request;
        if (! $request->client->requiresConsent) {
            return null;
        }
        if ($interaction->consent !== null) {
            return null;
        }
        if ($request->hasPrompt(Prompt::Consent)) {
            return ConsentRequirement::ConsentRequested;
        }
        $consent = $this->consents->findActive($session->user, $request->client);
        if ($consent === null || ! $consent->covers($request->scopes)) {
            return ConsentRequirement::NotGranted;
        }
        $interaction->consent($consent, $now);

        return null;
    }
}
