<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Introspection;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\JwsSignerInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Introspection\IntrospectionResponse;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\EndpointLocatorInterface;

/**
 * The introspection endpoint (RFC 7662 §2, architecture §4.12). The caller is a confidential client (§2.1);
 * a token is described to the client it was issued to and to nobody else (§2.2, §4); "token_type_hint" is
 * ignored. When asked, the answer is signed as RFC 9701 §4 and §5 describe.
 *
 * A token bound to a certificate (RFC 8705 §3) is described here whatever the caller presented: the
 * answer carries the "cnf" the resource server needs to make its own check (§3.2), and the client that
 * was issued the token is entitled to read it back whichever way it authenticated itself today.
 */
final readonly class IntrospectionHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private AccessTokenInspector $tokens,
        private JwsSignerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param bool $signed a signed response was asked for (RFC 9701 §4)
     * @param ClientCertificate|null $certificate the certificate the caller presented at the TLS handshake (RFC 8705 §2)
     *
     * @throws OAuth2Exception invalid_client or invalid_request; never for a token that is not active
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        bool $signed,
        ?ClientCertificate $certificate = null,
    ): IntrospectionResponse {
        $caller = $this->clients->authenticate(
            $tenant,
            $this->endpoints->locate($tenant)->introspection,
            $authorizationHeader,
            $parameters,
            $context,
            $certificate,
        )->client;
        if ($caller->registration->isPublic()) {
            throw new InvalidClientException('The introspection endpoint requires client authentication (RFC 7662 section 2.1); a public client has none.');
        }
        $request = RequestParameters::of($parameters);
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
            'aud' => $caller->registration->clientId,
            'iat' => $context->receivedAt->getTimestamp(),
            'token_introspection' => $response->members,
        ]);

        return $response->signed($this->signer->sign($tenant, $this->algorithms->defaultAlgorithm(), $payload, [
            'typ' => IntrospectionResponse::JWT_TYPE,
        ]));
    }
}
