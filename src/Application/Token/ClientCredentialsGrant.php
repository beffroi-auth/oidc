<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Application\Client\AuthenticatedClient;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTargetException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.4 (architecture §4.5): the client asks for itself, there being no user to ask and nobody to
 * send anywhere. The answer is an access token and nothing else, no ID token and no refresh token (§4.4.3),
 * and what the token stands on is the registration of the client itself.
 *
 * The client authenticates itself (§4.4), so a public client is refused here as it is refused a
 * registration for this grant. What the token is addressed to is asked for and never assumed: a request
 * that names no resource is refused rather than answered with a token addressed to the client that asked
 * for it (RFC 8707 §2, and the rule of TokenAudience), because a token no resource server is meant to
 * accept is the one thing this grant must not hand out. The scopes are asked for the same way and for the
 * same reason: what a request does not name, it is not granted.
 *
 * "openid" is refused: there is no ID token to issue and nobody to describe (OIDC Core §2), so a request
 * that asks for it asks for something this grant cannot answer, and it is told so rather than served a
 * token that looks like an authentication.
 *
 * The client is named in the "sub" of the tokens it gets (RFC 9068 §2.2), so one named in a way a subject
 * cannot be is refused a registration for this grant where a registration meets the wiring; here that is
 * settled and ClientSubject is the invariant behind it.
 */
final readonly class ClientCredentialsGrant implements ActsForTheClientItselfInterface
{
    public function __construct(
        private TokenIssuer $issuer,
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
        if ($registration->isPublic()) {
            throw new InvalidClientException('This grant type requires client authentication, and the client authenticated as a public client (RFC 6749 section 4.4).');
        }
        $authorization = new ClientAuthorization(
            $this->grantType(),
            Uuid::v7(),
            $client->client,
            self::scopes($request->required('scope'), $registration),
            self::resources($request, $registration),
            $client->confirmation,
        );

        return $this->issuer->issue($authorization, null, $context, $this->clock->now());
    }

    /**
     * RFC 6749 §3.3, §4.4.2: the scopes the request asks for, among the ones the client registered. The
     * parameter is optional in the specification and required here, for the reason the resources are: a
     * request that named nothing would otherwise be answered with everything the client is registered for.
     *
     * @throws InvalidScopeException when it is not a list of scope tokens, when it names a scope the client
     *                               is not registered for, or when it names "openid"
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
            throw new InvalidScopeException('The requested scope is not allowed for this client.');
        }

        return $scopes;
    }

    /**
     * RFC 8707 §2: the resources the request names, among the ones the client registered, at least one.
     *
     * @throws InvalidTargetException when the request names no resource, or one the client did not register
     */
    private static function resources(RequestParameters $request, ClientRegistration $registration): ResourceIndicators
    {
        $registered = $registration->resources === [] ? null : new ResourceIndicators($registration->resources);

        return RequestedResources::of($request, $registered) ?? throw InvalidTargetException::missing();
    }
}
