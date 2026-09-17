<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Introspection;

use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\JwsSignerInterface;
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
 * The introspection endpoint (RFC 7662 §2, architecture §4.12): a resource server that holds an opaque
 * access token, or a self-contained one it would rather not verify itself, asks the provider what the
 * token is. The caller is authenticated first, as a client, with a secret: §2.1 requires it against
 * token scanning, and a public client has nothing to authenticate with, so it is refused. Then the token
 * is inspected the way UserInfo inspects one (verified in its shape, its grant alive, its user served),
 * and answered with what the provider knows of it, or with "active": false and nothing else.
 *
 * A token is described to the client it was issued to and to nobody else: "aud" is that client until a
 * "resource" parameter says otherwise (RFC 8707, later), and a caller that is not in the audience of a
 * token learns nothing from it, not even that it exists (§2.2, §4). "token_type_hint" is read as a
 * string and then ignored: the shape of a token is told from the token itself, which §2.1 allows.
 *
 * When asked, the answer is signed (RFC 9701 §4, §5): the members travel as the "token_introspection"
 * claim of a JWT that names the provider as "iss", the caller as "aud" and the moment as "iat", under
 * the active key of the tenant, with the "typ" of §5, which is what Symfony's Oauth2TokenHandler verifies.
 * Nothing is written and nothing is announced: this is a read.
 */
final readonly class IntrospectionHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private AccessTokenInspector $tokens,
        private JwsSignerInterface $signer,
        private SignatureAlgorithm $algorithm = SignatureAlgorithm::RS256,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the decoded application/x-www-form-urlencoded body
     * @param bool $signed whether the caller asked for a signed response (RFC 9701 §4, the Accept header)
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

        return $response->signed($this->signer->sign($tenant, $this->algorithm, $payload, [
            'typ' => IntrospectionResponse::JWT_TYPE,
        ]));
    }
}
