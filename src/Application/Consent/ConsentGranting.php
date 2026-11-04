<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Consent;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class ConsentGranting
{
    public function __construct(
        private ConsentRepositoryInterface $consents,
        private UuidGeneratorInterface $uuids,
        private EventDispatcherInterface $events,
    ) {
    }

    public function grant(
        AuthenticationSession $session,
        Client $client,
        Scopes $scopes,
        ?AuthorizationDetails $authorizationDetails,
        ClaimNames $claims,
        RequestContext $context,
        DateTimeImmutable $now,
    ): Consent {
        $previous = $this->consents->findActive($session->user, $client);
        if ($previous === null) {
            $consent = new Consent($this->uuids->timeOrdered(), $session->user, $client, $scopes, $now, $authorizationDetails, $claims);
        } else {
            $consent = $previous->extendedWith($scopes, $authorizationDetails, $claims, $this->uuids->timeOrdered(), $now);
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
            $consent->claims,
            $previous?->id,
            $context,
        ));

        return $consent;
    }
}
