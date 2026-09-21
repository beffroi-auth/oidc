<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Introspection;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Application\Token\TokenRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Introspection\IntrospectionResponse;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;

/**
 * The introspection endpoint (RFC 7662 §2, architecture §4.12). The caller is a confidential client (§2.1);
 * a token is described to the client it was issued to and to nobody else (§2.2, §4); "token_type_hint" is
 * ignored. When asked, the answer is signed as RFC 9701 §4 and §5 describe.
 */
final readonly class IntrospectionHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private AccessTokenInspector $tokens,
        private JwsSignerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param bool $signed a signed response was asked for (RFC 9701 §4)
     *
     * @throws OAuth2Exception invalid_client or invalid_request; never for a token that is not active
     */
    public function handle(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context, bool $signed): IntrospectionResponse
    {
        $caller = $this->clients->authenticate($tenant, $authorizationHeader, $parameters, $context);
        if ($caller->isPublic()) {
            throw new InvalidClientException('The introspection endpoint requires client authentication (RFC 7662 section 2.1); a public client has none.');
        }
        $request = new TokenRequest($parameters);
        $token = $request->required('token');
        $request->optional('token_type_hint');
        $response = $this->describe($tenant, $caller, $token, $context);

        return $signed ? $this->sign($tenant, $caller, $response, $context) : $response;
    }

    private function describe(Tenant $tenant, Client $caller, string $token, RequestContext $context): IntrospectionResponse
    {
        try {
            $inspected = $this->tokens->inspect($tenant, $token, $context->receivedAt);
        } catch (InvalidTokenException) {
            return IntrospectionResponse::inactive();
        }
        if (! $inspected->token->client->equals($caller)) {
            return IntrospectionResponse::inactive();
        }

        return IntrospectionResponse::active($inspected->token, $tenant->issuer);
    }

    private function sign(Tenant $tenant, Client $caller, IntrospectionResponse $response, RequestContext $context): IntrospectionResponse
    {
        $payload = JwtPayload::encode([
            'iss' => (string) $tenant->issuer,
            'aud' => $caller->clientId,
            'iat' => $context->receivedAt->getTimestamp(),
            'token_introspection' => $response->members,
        ]);

        return $response->signed($this->signer->sign($tenant, $this->algorithms->defaultAlgorithm(), $payload, [
            'typ' => IntrospectionResponse::JWT_TYPE,
        ]));
    }
}
