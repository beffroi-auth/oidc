<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Consent;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\UuidGeneratorInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Event\ConsentGranted;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * What a user agreeing to a request comes to (architecture §4.3): the consent in force extended with the
 * scopes of that request, or a first one when they had granted nothing yet, and the event that says so.
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

    public function grant(AuthenticationSession $session, Client $client, Scopes $scopes, RequestContext $context, DateTimeImmutable $now): Consent
    {
        $previous = $this->consents->findActive($session->user, $client);
        if ($previous === null) {
            $consent = new Consent($this->uuids->timeOrdered(), $session->user, $client, $scopes, $now);
        } else {
            $consent = $previous->extendedWith($scopes, $this->uuids->timeOrdered(), $now);
            $this->consents->save($previous);
        }
        $this->consents->save($consent);
        $this->events->dispatch(new ConsentGranted(
            $consent->grantedAt,
            $consent->tenant,
            $consent->id,
            $consent->clientId,
            $consent->user->id,
            $consent->scopes,
            $previous?->id,
            $context,
        ));

        return $consent;
    }
}
