<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Device;

use function array_any;
use Beffroi\Oidc\Application\Administration\AdministrationAudience;
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
 * RFC 8628 §3.1, §3.2
 */
final readonly class DeviceAuthorizationHandler
{
    private const int DRAWS = 8;

    /**
     * @param positive-int $interval seconds between two polls
     *
     * @throws InvalidArgumentException when the interval is out of the bounds of a record
     */
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private ServedGrantsInterface $grants,
        private DeviceAuthorizationRecordRepositoryInterface $records,
        private SecretDrawer $secrets,
        private UserCodeDrawer $userCodes,
        private UuidGeneratorInterface $uuids,
        private AdministrationAudience $administration,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT10M'),
        public int $interval = DeviceAuthorizationRecord::DEFAULT_INTERVAL,
    ) {
        DeviceAuthorizationRecord::assertInterval($interval);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception
     * @throws RuntimeException when no free code could be drawn
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

        $request = RequestParameters::of($parameters);
        $scopes = self::scopes($request->required('scope'), $registration);
        $resources = self::resources($request, $registration);
        $this->administration->assertNotNamedIn($client->tenant, $resources);

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
     * Required though optional in RFC 8628 §3.1: none would ask the user to agree to all the client registered.
     *
     * @throws InvalidScopeException
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
     * Unique among the records kept, or one answer on the page could approve two requests.
     *
     * @throws RuntimeException
     */
    private function drawAUserCode(): UserCode
    {
        for ($draw = 0; $draw < self::DRAWS; ++$draw) {
            $userCode = $this->userCodes->draw();
            if (! $this->records->holdsUserCode($userCode->hash())) {
                return $userCode;
            }
        }

        throw new RuntimeException('No user code could be drawn that this provider does not already hold.');
    }
}
