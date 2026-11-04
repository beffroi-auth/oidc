<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Consent;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\ConsentRequirement;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;

/**
 * RFC 9396 §7, OIDC Core §3.1.2.4, §5.5
 */
final readonly class RequiredConsent
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private ClaimsAskedByName $claims,
    ) {
    }

    /**
     * @return ConsentRequirement|null null when none is needed, any consent in force then put on the interaction
     */
    public function of(Interaction $interaction, AuthenticationSession $session, DateTimeImmutable $now): ?ConsentRequirement
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
        if (
            $consent === null
            || ! $consent->scopes->covers($request->scopes)
            || ! $consent->coversAuthorizationDetails($request->authorizationDetails)
            || ! $this->claims->agreedIn($consent, $request)
        ) {
            return ConsentRequirement::NotGranted;
        }
        $interaction->consent($consent, $now);

        return null;
    }
}
