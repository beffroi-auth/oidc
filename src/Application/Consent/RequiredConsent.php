<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Consent;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Interaction\ConsentRequirement;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Port\ConsentRepositoryInterface;

/**
 * Whether a consent page is still needed, and what for (architecture §4.3): the counterpart of
 * ConsentGranting, which records the answer. A client the deployment named first-party needs none
 * (decision 0008), a consent given during this interaction is the answer, prompt=consent asks again
 * whatever is in force, and a consent in force that covers the scopes and the authorization details of the
 * request is carried by the interaction rather than asked for again.
 *
 * A request that asks for a detail the consent in force does not carry asks again (RFC 9396 §7), whichever
 * of the two it is: the scopes say what kind of thing the client may do and the details say what it may do
 * to what, so a consent covers a request when it covers both.
 *
 * Whether the page may be shown at all is prompt=none's (OIDC Core §3.1.2.6) and the handler's: this says
 * what is needed and never what to do about it.
 */
final readonly class RequiredConsent
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
    ) {
    }

    /**
     * @return ConsentRequirement|null null when nothing more is needed, the consent in force having been
     *                                carried by the interaction when there was one
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
        if ($consent === null || ! $consent->scopes->covers($request->scopes) || ! $consent->coversAuthorizationDetails($request->authorizationDetails)) {
            return ConsentRequirement::NotGranted;
        }
        $interaction->consent($consent, $now);

        return null;
    }
}
