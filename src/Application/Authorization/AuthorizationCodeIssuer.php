<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\UuidGeneratorInterface;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationResponse;
use Heidi\Oidc\Domain\Authorization\RequestedAuthenticationContext;
use Heidi\Oidc\Domain\Event\AuthorizationCodeIssued;
use Heidi\Oidc\Domain\Interaction\Granted;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidRequestUriException;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Mints what an interaction that needs nothing more has earned (architecture §4.3, §4.4): the counterpart of
 * TokenIssuer at the other endpoint. The code is drawn where every value this provider hands out is drawn, the
 * record is the grant the tokens of that code will descend from, the reference the request was pushed under is
 * spent here, and the event is dispatched with what it carries.
 *
 * The record freezes what the session had proven at this moment (AuthenticationSnapshot): a re-authentication
 * or a step-up afterwards moves the session and never a code already issued. The event is raised here, where
 * the code is, and carries what it carries by identifier: never the value the client was handed.
 */
final readonly class AuthorizationCodeIssuer
{
    public function __construct(
        private AuthorizationCodeRepositoryInterface $codes,
        private PushedAuthorizationRecordRepositoryInterface $pushedRecords,
        private SecretDrawer $secrets,
        private UuidGeneratorInterface $uuids,
        private EventDispatcherInterface $events,
        private DateInterval $lifetime = new DateInterval('PT60S'),
    ) {
    }

    /**
     * @throws InvalidRequestUriException when another request has already been granted on the reference this
     *                                   one was pushed under (RFC 9126 §4)
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
            $request->nonce,
            $request->codeChallenge,
            $request->dpopKey,
            $request->claims,
            AuthenticationSnapshot::ofSession($session, $context->classFor($session)),
            $now,
            $now->add($this->lifetime),
        );
        $this->codes->save($record);
        // RFC 9126 §4, FAPI 2.0 Security Profile §5.3.1: the reference is spent here, with the code it
        // bought, and not when the endpoint read it. A record the winner of the claim did not get is one
        // another request granted first, and this one grants nothing.
        if (! $this->spend($interaction, $now)) {
            throw new InvalidRequestUriException('The request_uri parameter names a request this provider has already granted (RFC 9126 section 4).');
        }

        $this->events->dispatch(new AuthorizationCodeIssued(
            $record->issuedAt,
            $record->tenant,
            $record->clientId,
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

    /**
     * The record an interaction was started from, claimed atomically: of any number of interactions that
     * reached this point on one reference, exactly one is told true (RFC 9126 §4). An interaction that was not
     * started from a record has nothing to spend and is told true.
     */
    private function spend(Interaction $interaction, DateTimeImmutable $now): bool
    {
        if ($interaction->requestUriHash === null) {
            return true;
        }
        $record = $this->pushedRecords->findByRequestUriHash($interaction->requestUriHash);

        return $record !== null && $this->pushedRecords->consume($record, $now);
    }
}
