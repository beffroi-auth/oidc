<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\UserInfo;

use function array_fill_keys;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\BearerToken;
use Heidi\Oidc\Domain\UserInfo\UserInfoResponse;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * The UserInfo endpoint (OIDC Core §5.3, architecture §4.7): a bearer token (RFC 6750 §2) inspected as
 * an access token of the provider, answered with the claims its scopes stand for (§5.4) and those asked
 * for by name (§5.5). A token without "openid" is insufficient_scope (§5.3.1). Errors are the ones of
 * RFC 6750 §3.1.
 */
final readonly class UserInfoHandler
{
    public function __construct(
        private AccessTokenInspector $tokens,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body, never the query string (RFC 6750 §2.3)
     *
     * @throws MissingBearerTokenException 401 with a bare challenge
     * @throws OAuth2Exception invalid_request, invalid_token or insufficient_scope
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context): UserInfoResponse
    {
        $bearer = BearerToken::fromRequest($authorizationHeader, $parameters);
        if ($bearer === null) {
            throw new MissingBearerTokenException();
        }
        $inspected = $this->tokens->inspect($tenant, $bearer->value, $context->receivedAt);
        $token = $inspected->token;
        if (! $token->hasScope(Scope::openid())) {
            throw new InsufficientScopeException('The access token was not obtained through an OpenID Connect authentication request.', [Scope::openid()]);
        }
        $user = $inspected->user;

        $requested = array_fill_keys($token->userinfoClaims, new ClaimRequest());

        return new UserInfoResponse(
            $this->subjects->resolve($user, $token->client)
                ->value,
            $this->claims->claims($user, $token->scopes, $requested),
        );
    }
}
