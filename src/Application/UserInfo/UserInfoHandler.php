<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\UserInfo;

use function array_fill_keys;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Token\AccessTokenVerifier;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\BearerToken;
use Heidi\Oidc\Domain\UserInfo\UserInfoResponse;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * The UserInfo endpoint (OIDC Core §5.3, architecture §4.7): a protected resource of the provider that
 * takes a bearer token (RFC 6750 §2), verifies it as one of its own access tokens, and answers with the
 * claims about the end user that the token entitles the client to: those the scopes of the token stand
 * for (§5.4) and those the client asked for by name (§5.5), read from the token itself, plus "sub"
 * through the same resolver that wrote it into the tokens, so that both name the same subject (§5.3.2).
 *
 * A token without "openid" opens nothing here (§5.3.1: "the Access Token obtained through an OpenID
 * Connect Authentication Request"): insufficient_scope, 403. A token whose user is gone or disabled is
 * refused like a bad one: invalid_token. Nothing is written and nothing is announced: this is a read.
 * Errors are the ones of RFC 6750 §3.1, never a redirect: the integration turns the exception into a
 * UserInfoErrorResponse.
 */
final readonly class UserInfoHandler
{
    public function __construct(
        private AccessTokenVerifier $tokens,
        private UserRepositoryInterface $users,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the decoded application/x-www-form-urlencoded body, if any; never the query string (RFC 6750 §2.3)
     *
     * @throws MissingBearerTokenException when the request carries no bearer token: 401, bare challenge
     * @throws OAuth2Exception invalid_request, invalid_token or insufficient_scope
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context): UserInfoResponse
    {
        $bearer = BearerToken::fromRequest($authorizationHeader, $parameters);
        if ($bearer === null) {
            throw new MissingBearerTokenException();
        }
        $token = $this->tokens->verify($tenant, $bearer->value, $context->receivedAt);
        if (! $token->hasScope(Scope::openid())) {
            throw new InsufficientScopeException('The access token was not obtained through an OpenID Connect authentication request.', [Scope::openid()]);
        }
        $user = $this->users->findBySubject($tenant, $token->subject);
        if ($user === null || ! $user->isEnabled()) {
            throw new InvalidTokenException('The access token names a user this provider no longer serves.');
        }

        // §5.5.1 "essential", "value" and "values" are not read by the provider, so the names are enough to ask again
        $requested = array_fill_keys($token->userinfoClaims, new ClaimRequest());

        return new UserInfoResponse(
            $this->subjects->resolve($user, $token->client)
                ->value,
            $this->claims->claims($user, $token->scopes, $requested),
        );
    }
}
