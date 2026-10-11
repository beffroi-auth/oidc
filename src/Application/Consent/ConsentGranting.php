<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Consent;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * What a user agreeing to a request comes to (architecture §4.3): the consent in force extended with the
 * scopes and the authorization details of that request, or a first one when they had granted nothing yet,
 * and the event that says so.
 *
 * Recorded here whichever page asked, the consent page of a browser flow or the page an appliance sends
 * its user to (RFC 8628 §3.3): a consent is the same fact however it was obtained, and what a user agreed
 * to is never taken back by a new agreement.
 */
final readonly class ConsentGranting
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private UuidGeneratorInterface $uuids,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param AuthorizationDetails|null $authorizationDetails what the request asked for beyond its scopes
     *                                                        (RFC 9396 §2), null when it asked for none
     */
    public function grant(
        AuthenticationSession $session,
        Client $client,
        Scopes $scopes,
        ?AuthorizationDetails $authorizationDetails,
        RequestContext $context,
        DateTimeImmutable $now,
    ): Consent {
        $previous = $this->consents->findActive($session->user, $client);
        if ($previous === null) {
            $consent = new Consent($this->uuids->timeOrdered(), $session->user, $client, $scopes, $now, $authorizationDetails);
        } else {
            $consent = $previous->extendedWith($scopes, $authorizationDetails, $this->uuids->timeOrdered(), $now);
            $this->consents->save($previous);
        }
        $this->consents->save($consent);
        $this->events->dispatch(new ConsentGranted(
            $consent->grantedAt,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $consent->user->subject,
            $consent->scopes,
            $consent->authorizationDetails,
            $previous?->id,
            $context,
        ));

        return $consent;
    }
}
