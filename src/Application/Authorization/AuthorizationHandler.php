<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\CredentialRepositoryInterface;
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
use Heidi\Oidc\Domain\Interaction\StepUp;
use Heidi\Oidc\Exception\AccessDeniedException;
use Heidi\Oidc\Exception\ConsentRequiredException;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\InvalidRequestUriException;
use Heidi\Oidc\Exception\LoginRequiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnmetAuthenticationRequirementsException;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use Heidi\Oidc\Port\ProvableMethodsInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Decides what a validated authorization request still needs (architecture §4.3): a login, a consent, or
 * nothing, in which case the code is issued. begin() parks the request in an Interaction; resume(),
 * grantConsent() and deny() apply the same rules at every step. With prompt=none a needed page is the
 * redirected error login_required or consent_required (OIDC Core §3.1.2.6). A requested "acr" is read
 * against the policy of the tenant (decision 0010): refused before any login when the provider can prove
 * none of the requested classes, then against what the user of the session can still prove with the
 * credentials they hold: refused before any page when none of them would satisfy a requested class and
 * the request is essential, answered with what the session has when it is voluntary, a step-up when one would.
 */
final readonly class AuthorizationHandler
{
    private const string LOGIN_REQUIRED = 'The end user is not authenticated as the request demands and prompt=none forbids asking.';

    private const string CONSENT_REQUIRED = 'No consent covers the request and prompt=none forbids asking.';

    private const string ACCESS_DENIED = 'The end user denied the request.';

    private const string UNMET_AUTHENTICATION_REQUIREMENTS = 'No requested acr value is one this provider can assert, see acr_values_supported.';

    private const string UNMET_BY_THE_USER = 'The end user holds no credential able to satisfy any requested acr value.';

    private const string UNMET_AFTER_LOGIN = 'The end user did not authenticate as any requested acr value demands.';

    public function __construct(
        private InteractionRepositoryInterface $interactions,
        private ConsentRepositoryInterface $consents,
        private AuthorizationCodeRepositoryInterface $codes,
        private PushedAuthorizationRequestRepositoryInterface $pushedRequests,
        private IdTokenHintVerifier $idTokenHints,
        private ProvableMethodsInterface $provable,
        private CredentialRepositoryInterface $credentials,
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
    public function begin(
        AuthorizationRequest $request,
        ?AuthenticationSession $session,
        RequestContext $context,
        ?string $locale = null,
        ?string $requestUriHash = null,
    ): AuthorizationDecision {
        $now = $this->clock->now();
        $interaction = new Interaction(
            Interaction::generateId(),
            $request->client->tenant,
            $request,
            $locale,
            $now,
            $now->add($this->interactionLifetime),
            $requestUriHash,
        );

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
        $this->events->dispatch(ConsentGranted::of($consent, $previous, $context));
        $interaction->consent($consent, $now);

        return $this->decide($interaction, $session, $context, $now);
    }

    /**
     * The record an interaction was started from, claimed atomically: of any number of interactions that
     * reached this point on one reference, exactly one is told true (RFC 9126 §4). An interaction that
     * was not started from a record has nothing to spend and is told true.
     */
    private function spend(Interaction $interaction, DateTimeImmutable $now): bool
    {
        if ($interaction->requestUriHash === null) {
            return true;
        }
        $record = $this->pushedRequests->findByRequestUriHash($interaction->requestUriHash);

        return $record !== null && $this->pushedRequests->consume($record, $now);
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
        $provableClasses = $requestedClasses->among($request->client->tenant->authenticationContextPolicy->provableWith($this->provable->provableMethods()));
        try {
            // before anything else: a forged hint is refused without a login
            $hinted = $request->idTokenHint === null ? null : $this->idTokenHints->verify($request->client, $request->idTokenHint);
            $this->assertCanBeMet($requestedClasses, $provableClasses);
            if ($session === null || ! $session->isActive($now)) {
                return $this->loginRequired($interaction, LoginRequirement::NoSession);
            }
            $stepUp = $this->stepUp($requestedClasses, $provableClasses, $session);
            $this->assertCanBeMetByTheUser($requestedClasses, $session, $stepUp);
            $loginRequirement = $this->loginRequirement($interaction, $session, $hinted, $stepUp, $now);
            if ($loginRequirement !== null) {
                return $this->loginRequired($interaction, $loginRequirement, $loginRequirement === LoginRequirement::StrongerFactorRequired ? $stepUp : null);
            }
            $this->assertMet($requestedClasses, $session);
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
            $request->dpopKey,
            $request->claims,
            AuthenticationSnapshot::ofSession($session, $requestedClasses->firstSatisfiedBy($session) ?? $session->authenticationContextClass()),
            $now,
            $now->add($this->codeLifetime),
        );
        $this->codes->save($record);
        // RFC 9126 §4, FAPI 2.0 Security Profile §5.3.1: the reference is spent here, with the code it
        // bought, and not when the endpoint read it. A record the winner of the claim did not get is one
        // another request granted first, and this one grants nothing.
        if (! $this->spend($interaction, $now)) {
            throw new InvalidRequestUriException('The request_uri parameter names a request this provider has already granted (RFC 9126 section 4).');
        }
        $interaction->complete($now);
        $this->interactions->save($interaction);
        $this->events->dispatch(AuthorizationCodeIssued::of($record, $context));

        return new Granted($interaction, $record, new AuthorizationResponse($request->client->tenant->issuer, $request->redirectUri, $request->state, $code));
    }

    /**
     * @throws LoginRequiredException when prompt=none forbids the login page
     */
    private function loginRequired(Interaction $interaction, LoginRequirement $requirement, ?StepUp $stepUp = null): LoginRequired
    {
        if ($interaction->request->hasPrompt(Prompt::None)) {
            throw new LoginRequiredException(self::LOGIN_REQUIRED);
        }
        $this->interactions->save($interaction);

        return new LoginRequired($interaction, $requirement, $stepUp);
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" naming only classes the provider cannot assert fails without a
     * login; a voluntary one is never refused.
     *
     * @param list<AuthenticationContextClass> $provable the requested classes the provider can prove
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    private function assertCanBeMet(AuthenticationContextRequest $requested, array $provable): void
    {
        if ($requested->demandsAClass() && $provable === []) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AUTHENTICATION_REQUIREMENTS);
        }
    }

    /**
     * Decision 0010: the client asked for classes the provider can prove, the session satisfies none and a
     * credential of the user would, so the login page asks for what is missing rather than for a new
     * login. The credentials are read only when a class is in question.
     *
     * @param list<AuthenticationContextClass> $provable the requested classes the provider can prove
     */
    private function stepUp(AuthenticationContextRequest $requested, array $provable, AuthenticationSession $session): ?StepUp
    {
        if ($provable === [] || $requested->firstSatisfiedBy($session) !== null) {
            return null;
        }

        return StepUp::towards($session->proofs, $provable, $this->credentials->findByUser($session->user));
    }

    /**
     * OIDC Core §5.5.1.1, as for a class the provider cannot prove: an essential "acr" the session does
     * not satisfy and no credential of the user could is a failed authentication before any page, the
     * user can do nothing about it there; a voluntary one gets the class the session has.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    private function assertCanBeMetByTheUser(AuthenticationContextRequest $requested, AuthenticationSession $session, ?StepUp $stepUp): void
    {
        if ($requested->demandsAClass() && $stepUp === null && $requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_BY_THE_USER);
        }
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" still unsatisfied once the login of this interaction is done
     * is a failed authentication; a voluntary one gets the class the session has.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    private function assertMet(AuthenticationContextRequest $requested, AuthenticationSession $session): void
    {
        if ($requested->demandsAClass() && $requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AFTER_LOGIN);
        }
    }

    /**
     * OIDC Core §3.1.2.1: a login done during this interaction satisfies prompt=login, max_age and a
     * step-up, whatever it proved; the step-up comes before prompt=login so that the page names what is
     * missing when a client sends both, as Symfony's re-authentication does.
     */
    private function loginRequirement(
        Interaction $interaction,
        AuthenticationSession $session,
        ?Subject $hinted,
        ?StepUp $stepUp,
        DateTimeImmutable $now,
    ): ?LoginRequirement {
        $request = $interaction->request;
        if ($hinted !== null && ! $session->user->subject->equals($hinted)) {
            return LoginRequirement::DifferentUser;
        }
        if ($session->authenticatedAt() >= $interaction->createdAt) {
            return null;
        }
        if ($stepUp !== null) {
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

    /**
     * Architecture §4.3: prompt=consent asks again unless the consent was given during this interaction.
     */
    private function consentRequirement(Interaction $interaction, AuthenticationSession $session, DateTimeImmutable $now): ?ConsentRequirement
    {
        $request = $interaction->request;
        if (! $request->client->registration->requiresConsent) {
            return null;
        }
        if ($interaction->consent !== null) {
            return null;
        }
        if ($request->hasPrompt(Prompt::Consent)) {
            return ConsentRequirement::ConsentRequested;
        }
        $consent = $this->consents->findActive($session->user, $request->client);
        if ($consent === null || ! $consent->scopes->covers($request->scopes)) {
            return ConsentRequirement::NotGranted;
        }
        $interaction->consent($consent, $now);

        return null;
    }
}
