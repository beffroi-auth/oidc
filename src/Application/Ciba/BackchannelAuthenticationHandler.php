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
 * CIBA Core §7
 *
 * An unknown user is answered like any other, never "unknown_user_id": that would tell whether the user exists.
 */
final readonly class BackchannelAuthenticationHandler
{
    private const string REQUESTED_EXPIRY_PATTERN = '/^[0-9]+$/D';

    /**
     * @param positive-int $interval seconds between two polls
     *
     * @throws InvalidArgumentException
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
        BackchannelAuthenticationRecord::assertInterval($interval);
    }

    /**
     * @param array<string, mixed> $parameters
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

        $parameters['client_id'] = $registration->clientId;
        $object = $this->readObject($tenant, $parameters, $client);
        $this->signedRequests->accept($object, $client);
        $request = RequestParameters::of($object->parameters ?? $parameters);

        // Read before anybody is looked up: a request refused here costs no lookup.
        $scopes = self::scopes($request->required('scope'), $registration);
        $resources = self::resources($request, $registration);
        $bindingMessage = self::bindingMessage($request);
        // acr_values is judged on the approval page, against the session of whoever answers, not here.
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
            // Kept, sealed, only for a client this provider calls back: the callback carries both values.
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
     * CIBA Core §13 has no "invalid_request_object", so a refused object is answered "invalid_request".
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
     * @throws InvalidScopeException
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
     * RFC 8707 §2
     *
     * @throws OAuth2Exception
     */
    private static function resources(RequestParameters $request, ClientRegistration $registration): ?ResourceIndicators
    {
        $registered = $registration->resources === [] ? null : new ResourceIndicators($registration->resources);

        return RequestedResources::of($request, $registered);
    }

    /**
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
     * Refused, never ignored: the client believes the request is bound to a secret the user knows.
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
