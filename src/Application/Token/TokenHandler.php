<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use function sprintf;

/**
 * The token endpoint (RFC 6749 §3.2, architecture §4.5): the client first, then the grant type, then the
 * grant. Errors are the ones of §5.2, never a redirect.
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
        private EndpointLocatorInterface $endpoints,
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
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake (RFC 8705 §2)
     *
     * @throws OAuth2Exception
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context, ?ClientCertificate $certificate = null): TokenResponse
    {
        $client = $this->clients->authenticate($tenant, $this->endpoints->locate($tenant)->token, $authorizationHeader, $parameters, $context, $certificate);
        $request = new TokenRequest($parameters);

        $grantType = GrantType::tryFrom($request->required('grant_type'));
        $grant = $grantType === null ? null : ($this->grants[$grantType->value] ?? null);
        if ($grantType === null || $grant === null) {
            throw new UnsupportedGrantTypeException('The grant type is not supported by this provider.');
        }
        if (! $client->client->allowsGrant($grantType)) {
            throw new UnauthorizedClientException('The client is not registered for this grant type.');
        }

        return $grant->grant($client, $request, $context)
            ->toResponse();
    }
}
