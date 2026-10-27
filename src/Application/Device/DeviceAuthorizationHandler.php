<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Device;

use function array_any;
use DateInterval;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Application\Secret\UserCodeDrawer;
use Beffroi\Oidc\Application\Token\RequestedResources;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\RuntimeException;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Psr\Clock\ClockInterface;

/**
 * The device authorization endpoint (RFC 8628 §3.1, §3.2): the front door of the flow for what has no
 * browser and no keyboard. The client first, authenticated exactly as at the token endpoint, then what it
 * asks for, then two codes, one it polls with and one its user types somewhere else.
 *
 * It is the endpoint of PushedAuthorizationHandler with a code beside the handle: an authenticated client,
 * a record with a lifetime, a reference answered back. Errors are the ones of RFC 6749 §5.2, in JSON, never
 * a redirect and never a page, this client having no browser to send anywhere.
 *
 * A client whose grants take no user on another device is refused here rather than served a code nothing
 * would ever spend; which grants those are is read where the token endpoint reads them, from the wiring.
 * The scopes are asked for and never assumed, as they are of a client acting for itself: what the user is
 * shown on the approval page is what the request named, and a request that named nothing would be a page
 * asking somebody to agree to everything the client ever registered.
 */
final readonly class DeviceAuthorizationHandler
{
    /**
     * How many times a code is drawn again when the draw collided with one still alive. A collision is a
     * one in twenty-five billion draw; what is refused rather than retried for ever is a store that hands
     * back the same code every time, which is a defect and not a collision.
     */
    private const int DRAWS = 8;

    /**
     * @param DateInterval $lifetime how long both codes live (RFC 8628 §3.2)
     * @param positive-int $interval the seconds a client is asked to wait between two polls (§3.5), held to the bound of a record when the handler is built rather than at the first request
     *
     * @throws InvalidArgumentException when the interval is one no request may be made with (DeviceAuthorizationRecord::assertInterval())
     */
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
        private DeviceAuthorizationRecordRepositoryInterface $records,
        private SecretDrawer $secrets,
        private UserCodeDrawer $userCodes,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT10M'),
        public int $interval = DeviceAuthorizationRecord::DEFAULT_INTERVAL,
    ) {
        DeviceAuthorizationRecord::assertInterval($interval);
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake (RFC 8705 §2)
     *
     * @throws OAuth2Exception
     * @throws RuntimeException when no code could be drawn that the store does not already hold
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
    ): DeviceAuthorizationResponse {
        $endpoints = $this->endpoints->locate($tenant);
        $client = $this->clients->authenticate($tenant, $endpoints->deviceAuthorization, $authorizationHeader, $parameters, $context, $certificate)->client;
        $registration = $client->registration;
        $asksTheUserElsewhere = array_any(
            $this->grants->askingTheUserOnAnotherDevice(),
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
        if (! $asksTheUserElsewhere) {
            throw new UnauthorizedClientException('The client is not registered for a grant that asks its user on another device (RFC 8628 section 3.1).');
        }

        // what the request asks for is read before anything is drawn for it: a request this endpoint
        // refuses spends none of the codes this provider hands out
        $request = RequestParameters::of($parameters);
        $scopes = self::scopes($request->required('scope'), $registration);
        $resources = self::resources($request, $registration);

        $now = $this->clock->now();
        $deviceCode = $this->secrets->draw();
        $userCode = $this->drawAUserCode();
        $record = new DeviceAuthorizationRecord(
            DrawnSecret::digestOf($deviceCode),
            $userCode->hash(),
            $this->uuids->timeOrdered(),
            $client,
            $scopes,
            $resources,
            $context,
            $now,
            $now->add($this->lifetime),
            $this->interval,
        );
        $this->records->save($record);

        return new DeviceAuthorizationResponse(
            $deviceCode,
            $userCode,
            $endpoints->deviceVerification,
            $record->expiresIn($now),
            $record->interval,
        );
    }

    /**
     * RFC 6749 §3.3: the scopes the request asks for, among the ones the client registered. The parameter
     * is optional in RFC 8628 §3.1 and required here, as it is of a client acting for itself: a request
     * that named nothing would be answered with everything the client is registered for, and shown to
     * somebody as what they are agreeing to.
     *
     * @throws InvalidScopeException when it is not a list of scope tokens, or names a scope the client is
     *                              not registered for
     */
    private static function scopes(string $scope, ClientRegistration $registration): Scopes
    {
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
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
     * A code no record still alive holds: the page the user types on looks a code up by itself, so two
     * live records carrying the same one would be two requests one answer could approve.
     *
     * @throws RuntimeException
     */
    private function drawAUserCode(): UserCode
    {
        for ($draw = 0; $draw < self::DRAWS; ++$draw) {
            $userCode = $this->userCodes->draw();
            $held = $this->records->findByUserCodeHash($userCode->hash());
            if ($held === null || $held->isExpired($this->clock->now())) {
                return $userCode;
            }
        }

        throw new RuntimeException('No user code could be drawn that this provider does not already hold.');
    }
}
