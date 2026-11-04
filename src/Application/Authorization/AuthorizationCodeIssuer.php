<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Claims\ClaimsAskedByName;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\AuthorizationResponse;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Beffroi\Oidc\Domain\Interaction\Granted;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidRequestUriException;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class AuthorizationCodeIssuer
{
    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private PushedAuthorizationRecordRepositoryInterface $pushedRecords,
        private SecretDrawer $secrets,
        private UuidGeneratorInterface $uuids,
        private EventDispatcherInterface $events,
        private ClaimsAskedByName $claims,
        private DateInterval $lifetime = new DateInterval('PT60S'),
    ) {
    }

    /**
     * @throws InvalidRequestUriException when another request was already granted on its request_uri
     */
    public function issue(
        Interaction $interaction,
        AuthenticationSession $session,
        RequestedAuthenticationContext $context,
        RequestContext $requestContext,
        DateTimeImmutable $now,
    ): Granted {
        $request = $interaction->request;
        $code = $this->secrets->draw();
        $record = new AuthorizationCode(
            DrawnSecret::digestOf($code),
            $this->uuids->timeOrdered(),
            $request->client,
            $session,
            $request->redirectUri,
            $request->scopes,
            $request->resources,
            $request->authorizationDetails,
            $request->nonce,
            $request->codeChallenge,
            $request->dpopKey,
            $this->claims->grantable($request->client, $request->claims),
            AuthenticationSnapshot::ofSession($session, $context->classFor($session)),
            $now,
            $now->add($this->lifetime),
        );
        $this->codes->save($record);
        // RFC 9126 §4: the request_uri is spent here, with the code it bought, not when the endpoint read it.
        if (! $this->spend($interaction, $now)) {
            throw new InvalidRequestUriException('The request_uri parameter names a request this provider has already granted (RFC 9126 section 4).');
        }

        $this->events->dispatch(new AuthorizationCodeIssued(
            $record->issuedAt,
            $record->tenant,
            $record->clientId,
            $record->session->user->subject,
            $record->grantId,
            $record->session->id,
            $record->codeHash,
            $record->scopes,
            $record->expiresAt,
            $requestContext,
        ));

        return new Granted(
            $interaction,
            $record,
            new AuthorizationResponse($request->client->tenant->issuer, $request->redirectUri, $request->state, $code),
        );
    }

    private function spend(Interaction $interaction, DateTimeImmutable $now): bool
    {
        if ($interaction->requestUriHash === null) {
            return true;
        }
        $record = $this->pushedRecords->findByRequestUriHash($interaction->requestUriHash);

        return $record !== null && $this->pushedRecords->consume($record, $now);
    }
}
