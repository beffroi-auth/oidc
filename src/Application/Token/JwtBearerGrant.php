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
 * RFC 7523 §2.1, §3 (architecture §4.5): the client presents an assertion signed by an issuer the tenant
 * trusts, and receives an access token for the user that assertion is about.
 *
 * It is one paragraph of a specification and a whole trust decision: whoever holds the signing key of a trusted
 * issuer can name a user of the tenant. So everything is registered in advance and nothing is asked for
 * (TrustedIssuer), the refusals say nothing of what is registered, and the subject of an assertion is a user of
 * this tenant only through a linked identity of that issuer's source (decision 0002). No user is created here:
 * an assertion about somebody no identity resolves is refused, as an assertion of an unknown issuer is.
 *
 * The assertion is the authorization and not the client authentication (RFC 7523 §2.1, last paragraph): the
 * client authenticates beside it as it does for every other grant, and the two readings of an assertion share
 * no validator, no registration and no replay guard, so that one cannot be taken for the other.
 *
 * No ID token, and "openid" refused with it: the user was authenticated somewhere else and this provider has
 * nothing to say about how, neither an "acr" nor an "amr" nor an "auth_time" being ours to claim (OIDC Core
 * §2). A client that wants a document describing a user signs that user in.
 */
final readonly class JwtBearerGrant implements GrantInterface
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
     * RFC 8707 §2 decides what the token is addressed to, here as in every grant with nobody's browser in it:
     * the resources the request names, among the ones the client registered, at least one. A token addressed to
     * the client that asked for it is a token no resource server is meant to accept.
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
            // the assertion was validated for a user of this tenant, so what it gets is written in the
            // journal of that person and not under the "sub" this client is answered (issue #588)
            person: $user->subject,
        );

        return $this->issuer->issue($authorization, null, $context, $now);
    }

    /**
     * RFC 7523 §3, decision 0002: the user the assertion is about, found by the linked identity of the source
     * the issuer is trusted for. An assertion about somebody no identity resolves, or about a user this
     * provider no longer serves, is refused exactly as an assertion of an unknown issuer is: what the tenant
     * knows is not something an error response teaches.
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
     * RFC 6749 §3.3, RFC 7523 §3: the scopes the request asks for, among the ones the client registered and the
     * ones the issuer is trusted for. The parameter is required here for the reason it is required of every
     * grant with no browser in it: a request that named nothing would otherwise be answered with everything two
     * registrations happen to have in common.
     *
     * "openid" asks for an authentication, and this grant performs none (OIDC Core §2): it is refused rather
     * than dropped from a response that would then look like one.
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
