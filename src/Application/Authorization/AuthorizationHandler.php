<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Application\Consent\RequiredConsent;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\ConsentRequired;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Interaction\LoginRequired;
use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\ConsentRequiredException;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\LoginRequiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * Decides what a validated authorization request still needs: a login, a consent, or the code.
 */
final readonly class AuthorizationHandler
{
    private const string LOGIN_REQUIRED = 'The end user is not authenticated as the request demands and prompt=none forbids asking.';

    private const string UNMET_BY_THE_LOGIN = 'The end user signed in during this interaction and is still not authenticated as the request demands.';

    private const string CONSENT_REQUIRED = 'No consent covers the request and prompt=none forbids asking.';

    private const string ACCESS_DENIED = 'The end user denied the request.';

    public function __construct(
        private InteractionRepositoryInterface $interactions,
        private ConsentGranting $consentGranting,
        private RequiredConsent $consent,
        private ClaimsAskedByName $claims,
        private SecretDrawer $secrets,
        private AuthenticationRequirement $authentication,
        private AuthorizationCodeIssuer $codes,
        private ClockInterface $clock,
        private DateInterval $interactionLifetime = new DateInterval('PT10M'),
    ) {
    }

    /**
     * @throws OAuth2Exception redirectable
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
            $this->secrets->draw(),
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

        $consent = $this->consentGranting->grant(
            $session,
            $interaction->request->client,
            $interaction->request->scopes,
            $interaction->request->authorizationDetails,
            $this->claims->toAgreeTo($interaction->request),
            $context,
            $now,
        );
        $interaction->consent($consent, $now);

        return $this->decide($interaction, $session, $context, $now);
    }

    /**
     * @throws InteractionCompletedException
     * @throws InteractionExpiredException
     * @throws AccessDeniedException
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
        try {
            $requested = $this->authentication->beforeAnyLogin($request);
            if ($session === null || ! $session->isActive($now)) {
                return $this->loginRequired($interaction, LoginRequirement::NoSession);
            }
            $login = $this->authentication->of($requested, $interaction, $session, $now);
            if ($login !== null) {
                // No second login page in one interaction: it would ask whoever signs in next the same thing.
                if ($interaction->sawTheLoginOf($session)) {
                    throw new LoginRequiredException(self::UNMET_BY_THE_LOGIN);
                }

                return $this->loginRequired($interaction, $login->requirement, $login->stepUp);
            }
            $requested->context->assertMetBy($session);
            $interaction->authenticate($session, $now);

            $consentRequirement = $this->consent->of($interaction, $session, $now);
            if ($consentRequirement !== null) {
                if ($request->hasPrompt(Prompt::None)) {
                    throw new ConsentRequiredException(self::CONSENT_REQUIRED);
                }
                $this->interactions->save($interaction);

                return new ConsentRequired(
                    $interaction,
                    $session,
                    $request->scopes,
                    $consentRequirement,
                    $request->authorizationDetails,
                    $this->claims->toAgreeTo($request),
                );
            }
            $granted = $this->codes->issue($interaction, $session, $requested->context, $context, $now);
        } catch (OAuth2Exception $exception) {
            $interaction->complete($now);
            $this->interactions->save($interaction);

            throw $exception;
        }
        $interaction->complete($now);
        $this->interactions->save($interaction);

        return $granted;
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
}
