<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use function sprintf;

/**
 * The token endpoint (RFC 6749 §3.2, architecture §4.5): the client is authenticated first, so that
 * nothing about the request is told to a caller that is not a client; then "grant_type" names a grant
 * the provider offers ("unsupported_grant_type" otherwise) and the client is registered for
 * ("unauthorized_client" otherwise); then the grant does the rest. Errors are the ones of §5.2, never a
 * redirect: the integration turns the exception into a TokenErrorResponse.
 */
final readonly class TokenHandler
{
    /**
     * @var array<string, GrantInterface> by grant type value
     */
    private array $grants;

    /**
     * @param iterable<GrantInterface> $grants
     */
    public function __construct(
        private ClientAuthenticator $clients,
        iterable $grants,
    ) {
        $indexed = [];
        foreach ($grants as $grant) {
            if (isset($indexed[$grant->grantType()->value])) {
                throw new InvalidArgumentException(sprintf('Two grants handle "%s".', $grant->grantType()->value));
            }
            $indexed[$grant->grantType()->value] = $grant;
        }
        $this->grants = $indexed;
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the decoded application/x-www-form-urlencoded body
     *
     * @throws OAuth2Exception
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context): TokenResponse
    {
        $client = $this->clients->authenticate($tenant, $authorizationHeader, $parameters, $context);
        $request = new TokenRequest($parameters);

        $grantType = GrantType::tryFrom($request->required('grant_type'));
        $grant = $grantType === null ? null : ($this->grants[$grantType->value] ?? null);
        if ($grantType === null || $grant === null) {
            throw new UnsupportedGrantTypeException('The grant type is not supported by this provider.');
        }
        if (! $client->allowsGrant($grantType)) {
            throw new UnauthorizedClientException('The client is not registered for this grant type.');
        }

        return $grant->grant($client, $request, $context)
            ->toResponse();
    }
}
