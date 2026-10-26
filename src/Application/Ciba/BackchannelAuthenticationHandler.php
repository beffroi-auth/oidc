<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function array_any;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Application\Authorization\ResolvedRequestObject;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Application\Token\RequestedResources;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationResponse;
use Beffroi\Oidc\Domain\Ciba\BindingMessage;
use Beffroi\Oidc\Domain\Ciba\ClientNotificationToken;
use Beffroi\Oidc\Domain\Ciba\NotifiesTheClientInterface;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidBindingMessageException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\PendingApprovalNotifierInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use function max;
use function min;
use function preg_match;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The backchannel authentication endpoint (CIBA Core §7): the front door of the one flow of this provider
 * where the authorization request arrives without a browser and the answer is waited for. The client
 * first, authenticated exactly as at the token endpoint, then the user it names, then a record nobody but
 * that user can answer.
 *
 * It is the endpoint of PushedAuthorizationHandler with a user beside the handle: an authenticated client,
 * a request that may itself be a signed object (RFC 9101 §6.1, which FAPI-CIBA §5.2.2 asks of every one
 * of them), a record with a lifetime, an identifier answered back. Errors are the ones of §13, in JSON,
 * never a redirect and never a page, this client having no browser to send anywhere; an object this
 * endpoint will not read is "invalid_request" there and not the "invalid_request_object" of the endpoint
 * a browser reaches.
 *
 * What it does not do is tell the client whether the user it named exists. §13 defines "unknown_user_id"
 * for exactly that, and serving it would say in one round trip what the whole login path of this provider
 * is built not to say (decision 0006, architecture §3.4): a request naming a stranger is answered with an
 * identifier like every other, and it then goes the way of every request nobody answers, to
 * "expired_token". What the client is told is bounded by the same load budget as every other endpoint of
 * the protocol plane (decision 0014), counted against the client it authenticated.
 */
final readonly class BackchannelAuthenticationHandler
{
    /**
     * CIBA Core §7.1 "requested_expiry": a positive integer of seconds and nothing else, read before it
     * is compared with anything.
     */
    private const string REQUESTED_EXPIRY_PATTERN = '/^[0-9]+$/D';

    /**
     * @param DateInterval $lifetime how long a request lives when the client asks for nothing (§7.3)
     * @param DateInterval $maxRequestedExpiry the longest this provider serves, whatever a client asks for (§7.1)
     * @param positive-int $interval the seconds a client is asked to wait between two polls (§7.3)
     */
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
        private RequestObjectResolver $requestObjects,
        private SignedBackchannelRequest $signedRequests,
        private UserHints $hints,
        private BackchannelAuthenticationRecordRepositoryInterface $records,
        private SecretDrawer $secrets,
        private UuidGeneratorInterface $uuids,
        private SecretSealerInterface $sealer,
        private PendingApprovalNotifierInterface $notifier,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT5M'),
        public DateInterval $maxRequestedExpiry = new DateInterval('PT30M'),
        public int $interval = BackchannelAuthenticationRecord::DEFAULT_INTERVAL,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake (RFC 8705 §2)
     *
     * @throws OAuth2Exception
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
    ): BackchannelAuthenticationResponse {
        $endpoints = $this->endpoints->locate($tenant);
        $client = $this->clients->authenticate(
            $tenant,
            $endpoints->backchannelAuthentication,
            $authorizationHeader,
            $parameters,
            $context,
            $certificate,
        )->client;
        $registration = $client->registration;
        $waitsForAnApproval = array_any(
            $this->grants->askingTheUserThroughABackchannel(),
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
        if (! $waitsForAnApproval) {
            throw new UnauthorizedClientException('The client is not registered for a grant that waits for its user to approve a request made elsewhere (CIBA Core section 7.1).');
        }
        $delivery =
            $registration->backchannelTokenDeliveryMode ?? throw new UnauthorizedClientException('The client registered no backchannel token delivery mode, and is told nothing about a request it could not be answered for (CIBA Core section 4).');

        // RFC 9101 §6.1: the request may itself be a signed object, which FAPI-CIBA §5.2.2 requires. It
        // is read here, against the client that has just authenticated, then what the object has to say
        // about itself is asked of it (CIBA Core §7.1.1), and what follows reads parameters as at every
        // other endpoint.
        $parameters['client_id'] = $registration->clientId;
        $object = $this->readObject($tenant, $parameters, $client);
        $this->signedRequests->accept($object, $client);
        $request = RequestParameters::of($object->parameters ?? $parameters);

        // what the request asks for is read before anything is drawn for it, and before anybody is
        // looked up: a request this endpoint refuses costs the provider no lookup at all
        $scopes = self::scopes($request->required('scope'), $registration);
        $resources = self::resources($request, $registration);
        $bindingMessage = self::bindingMessage($request);
        // CIBA Core §7.1 "acr_values": read here, with the rest of what the request asks for, and
        // carried on the record. Nothing is judged against it now: what a class is worth is what the
        // session of the person who answers proves, and that person is asked on a page (§4.14)
        $acrValues = $request->acrValues();
        $notificationToken = self::notificationToken($request, $delivery instanceof NotifiesTheClientInterface);
        self::refuseAUserCode($request);
        $now = $this->clock->now();
        $expiresAt = $this->expiryOf($request, $now);

        $user = $this->hints->userNamedBy($client, $request);
        $authRequestId = $this->secrets->draw();
        $record = new BackchannelAuthenticationRecord(
            DrawnSecret::digestOf($authRequestId),
            $this->uuids->timeOrdered(),
            $client,
            $user,
            $scopes,
            $resources,
            $bindingMessage,
            $acrValues,
            // a client this provider has to call back is the only reason it keeps what it handed out:
            // both values are sealed under the KMS of the tenant, as a shared secret of a user is
            // (architecture §3.3), and a client that only polls leaves neither behind
            $notificationToken === null ? null : $this->sealer->seal($tenant, $authRequestId),
            $notificationToken === null ? null : $this->sealer->seal($tenant, $notificationToken->value),
            $context,
            $now,
            $expiresAt,
            $this->interval,
        );
        $this->records->save($record);
        if ($user !== null) {
            $this->notifier->tell(new PendingApproval(
                $tenant,
                $user->id,
                $registration->presentation->name,
                $bindingMessage,
                $expiresAt,
                $endpoints->backchannelApproval,
            ));
        }

        return new BackchannelAuthenticationResponse($authRequestId, $record->expiresIn($now), $record->interval);
    }

    /**
     * CIBA Core §13 names the errors this endpoint answers, and "invalid_request_object" is not one of
     * them: that is the error of the authorization endpoint, where the parameter is "request" and the
     * refusal is a page (OIDC Core §6.1, RFC 9101 §5). Here an object the endpoint will not read is
     * "invalid_request", like every other request it will not read. What is refused and why stays the
     * resolver's; only the name of the error belongs to the endpoint that answers.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception
     */
    private function readObject(Tenant $tenant, array $parameters, Client $client): ?ResolvedRequestObject
    {
        try {
            return $this->requestObjects->resolve($tenant, $parameters, $client);
        } catch (InvalidRequestObjectException $exception) {
            throw new InvalidRequestException($exception->errorDescription, false, $exception);
        }
    }

    /**
     * CIBA Core §7.1: the scopes the request asks for, among the ones the client registered, "openid"
     * among them. There is no default: what the user is shown on the page where they approve is what the
     * request named, and a request that named nothing would be a page asking somebody to agree to
     * everything the client ever registered.
     *
     * @throws InvalidScopeException when it is not a list of scope tokens, names a scope the client is
     *                              not registered for, or does not ask for "openid"
     */
    private static function scopes(string $scope, ClientRegistration $registration): Scopes
    {
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
        }
        if (! $scopes->has(Scope::openid())) {
            throw new InvalidScopeException('A backchannel authentication request asks for the openid scope (CIBA Core section 7.1).');
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw InvalidScopeException::notRegistered();
        }

        return $scopes;
    }

    /**
     * RFC 8707 §2: the resources the request names, among the ones the client registered. A request that
     * names none is served all the same, there being a user behind this grant and therefore a client the
     * token can be addressed to (TokenAudience).
     *
     * @throws OAuth2Exception when a value is not an absolute URI, or names a resource the client did not register
     */
    private static function resources(RequestParameters $request, ClientRegistration $registration): ?ResourceIndicators
    {
        $registered = $registration->resources === [] ? null : new ResourceIndicators($registration->resources);

        return RequestedResources::of($request, $registered);
    }

    /**
     * CIBA Core §7.1, §13: optional, and refused rather than trimmed when it is not something a user can
     * be shown as it was sent.
     *
     * @throws OAuth2Exception
     */
    private static function bindingMessage(RequestParameters $request): ?BindingMessage
    {
        $value = $request->optional('binding_message');
        if ($value === null) {
            return null;
        }
        try {
            return new BindingMessage($value);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidBindingMessageException(
                'The binding message is not one that can be shown to a user as it was sent (CIBA Core section 7.1).',
                $exception,
            );
        }
    }

    /**
     * CIBA Core §7.1: required of a client that registered a mode where this provider calls it back,
     * refused from one that registered a mode where it does not. A client that only polls and sends a
     * token all the same is telling the provider to keep a credential it would never present, so it is
     * refused rather than ignored.
     *
     * @throws OAuth2Exception
     */
    private static function notificationToken(RequestParameters $request, bool $theClientIsCalledBack): ?ClientNotificationToken
    {
        $value = $request->optional('client_notification_token');
        if (! $theClientIsCalledBack) {
            if ($value !== null) {
                throw new InvalidRequestException('The client_notification_token parameter is for a client this provider calls back, and this client registered a mode where it does not (CIBA Core section 7.1).');
            }

            return null;
        }
        if ($value === null) {
            throw new InvalidRequestException('The client_notification_token parameter is missing, and this client registered a mode where this provider calls it back (CIBA Core section 7.1).');
        }
        try {
            return new ClientNotificationToken($value);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidRequestException(
                'The client_notification_token parameter is not a bearer token this provider could present back (CIBA Core section 7.1).',
                false,
                $exception,
            );
        }
    }

    /**
     * CIBA Core §7.1 "user_code": a secret of the user, sent by the client, that this provider does not
     * serve; the document says so ("backchannel_user_code_parameter_supported"). A request carrying one
     * is refused rather than served without it: the client believes the request is bound to something
     * the user knows, and answering it would be answering a request nobody made the way it was made.
     *
     * @throws OAuth2Exception
     */
    private static function refuseAUserCode(RequestParameters $request): void
    {
        if ($request->isPresent('user_code')) {
            throw new InvalidRequestException('This provider does not take a user_code on a backchannel authentication request, and says so in its metadata (CIBA Core section 7.1).');
        }
    }

    /**
     * CIBA Core §7.1 "requested_expiry": what the client asks the lifetime to be, capped at what this
     * provider serves. A request that asks for more is served the maximum rather than refused, §7.1
     * making the value a request and not a condition; one that asks for nothing at all, or for a value
     * that is not a number of seconds, is refused, because a client that wrote something there meant
     * something by it.
     *
     * @throws OAuth2Exception
     */
    private function expiryOf(RequestParameters $request, DateTimeImmutable $now): DateTimeImmutable
    {
        $maximum = $now->add($this->maxRequestedExpiry);
        $requested = $request->optional('requested_expiry');
        if ($requested === null) {
            return min($now->add($this->lifetime), $maximum);
        }
        if (preg_match(self::REQUESTED_EXPIRY_PATTERN, $requested) !== 1 || (int) $requested < 1) {
            throw new InvalidRequestException(sprintf(
                'The requested_expiry parameter is a positive number of seconds (CIBA Core section 7.1); at most %d are served.',
                $maximum->getTimestamp() - $now->getTimestamp(),
            ));
        }

        return min($now->add(new DateInterval(sprintf('PT%dS', max(1, (int) $requested)))), $maximum);
    }
}
