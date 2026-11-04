<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Psr\Clock\ClockInterface;

/**
 * RFC 6749 §4.4
 */
final readonly class ClientCredentialsGrant implements ActsForTheClientItselfInterface
{
    public function __construct(
        private TokenIssuer $issuer,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName('client_credentials');
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $registration = $client->client->registration;
        $authorization = new ClientAuthorization(
            $this->grantType(),
            $this->uuids->timeOrdered(),
            $client->client,
            self::scopes($request->required('scope'), $registration),
            self::resources($request, $registration),
            $client->confirmation,
        );

        return $this->issuer->issue($authorization, null, $context, $this->clock->now());
    }

    /**
     * RFC 6749 §3.3, §4.4.2
     *
     * Required, though RFC 6749 makes it optional: naming nothing would get every scope the client registered.
     *
     * @throws InvalidScopeException when it names a scope the client is not registered for, or "openid"
     */
    private static function scopes(string $scope, ClientRegistration $registration): Scopes
    {
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
        }
        if ($scopes->has(Scope::openid())) {
            throw new InvalidScopeException('The openid scope asks for an authentication, and this grant has no user to authenticate (OIDC Core section 2).');
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw InvalidScopeException::notRegistered();
        }

        return $scopes;
    }

    /**
     * RFC 8707 §2
     *
     * A resource is required: a token addressed to the client itself is one no resource server is meant to accept.
     *
     * @throws InvalidTargetException when the request names no resource, or one the client did not register
     */
    private static function resources(RequestParameters $request, ClientRegistration $registration): ResourceIndicators
    {
        $registered = $registration->resources === [] ? null : new ResourceIndicators($registration->resources);

        return RequestedResources::of($request, $registered) ?? throw InvalidTargetException::missing();
    }
}
