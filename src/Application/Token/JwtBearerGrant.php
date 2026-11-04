<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Trust\IssuerAssertionValidator;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Trust\VerifiedAssertion;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;
use Psr\Clock\ClockInterface;

/**
 * RFC 7523 §2.1, §3
 *
 * The assertion is spent last, once the response is addressed: a request refused on the way, or a KMS that does not
 * answer, leaves it to the next presentation.
 */
final readonly class JwtBearerGrant implements RequiresClientAuthenticationInterface
{
    public const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    public function __construct(
        private IssuerAssertionValidator $assertions,
        private LinkedIdentityRepositoryInterface $identities,
        private SubjectIdentifierResolverInterface $subjects,
        private TokenIssuer $issuer,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName(self::GRANT_TYPE);
    }

    /**
     * RFC 8707 §2
     *
     * A resource is required: a token addressed to the client itself is one no resource server is meant to accept.
     */
    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $tenant = $client->client->tenant;
        $verified = $this->assertions->validate($tenant, $client->client, $request->required('assertion'), $now);
        $user = $this->userOf($verified, $client);
        $registration = $client->client->registration;
        $registered = $registration->resources === [] ? null : new ResourceIndicators($registration->resources);
        $resources = RequestedResources::of($request, $registered);
        if ($resources === null || $registered === null) {
            throw InvalidTargetException::missing();
        }

        $authorization = new SubjectAuthorization(
            $this->grantType(),
            $this->uuids->timeOrdered(),
            $client->client,
            $this->subjects->resolve($user, $client->client),
            self::scopes($request, $verified, $registration),
            $verified->issuer->trustedScopes,
            $resources,
            $registered,
            confirmation: $client->confirmation,
            person: $user->subject,
        );
        $addressed = $this->issuer->addressFor($authorization);
        $this->assertions->spend($tenant, $verified);

        return $this->issuer->issue($authorization, null, $context, $now, $addressed);
    }

    /**
     * RFC 7523 §3
     *
     * An unresolved or unserved user is refused as an unknown issuer is: an error teaches nothing of the tenant.
     *
     * @throws InvalidGrantException
     */
    private function userOf(VerifiedAssertion $verified, AuthenticatedClient $client): User
    {
        $identity = $this->identities->find($client->client->tenant, $verified->issuer->identityProvider, $verified->subject);
        if ($identity === null || ! $identity->user->isEnabled()) {
            throw new InvalidGrantException('The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).');
        }

        return $identity->user;
    }

    /**
     * RFC 6749 §3.3, RFC 7523 §3
     *
     * Required: naming nothing would be answered with every scope two registrations share. "openid" is refused, not
     * dropped: this grant performs no authentication and must not look like one (OIDC Core §2).
     *
     * @throws InvalidScopeException
     */
    private static function scopes(RequestParameters $request, VerifiedAssertion $verified, ClientRegistration $registration): Scopes
    {
        try {
            $scopes = Scopes::parse($request->required('scope'));
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
        }
        if ($scopes->has(Scope::openid())) {
            throw new InvalidScopeException('The openid scope asks for an authentication, and this grant authenticates nobody: the assertion says somebody else did (OIDC Core section 2).');
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw InvalidScopeException::notRegistered();
        }
        if (! $verified->issuer->isTrustedFor($scopes)) {
            throw new InvalidScopeException('The requested scope is not one the issuer of the assertion is trusted for.');
        }

        return $scopes;
    }
}
