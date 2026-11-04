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
use Beffroi\Oidc\Domain\Event\IntrospectionAnswered;
use Beffroi\Oidc\Domain\Introspection\IntrospectionResponse;
use Beffroi\Oidc\Domain\Token\InspectedAccessToken;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 7662 §2, RFC 9701 §4, §5
 */
final readonly class IntrospectionHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private EndpointLocatorInterface $endpoints,
        private AccessTokenInspector $tokens,
        private JwsSignerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception invalid_client or invalid_request, never for a token that is not active
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
        $described = $this->tokenOfTheCaller($tenant, $caller, $token, $context);
        $response = $described === null
            ? IntrospectionResponse::inactive()
            : IntrospectionResponse::active($described->token, $tenant->issuer);
        $response = $signed ? $this->sign($tenant, $caller, $response, $context) : $response;
        $person = $described?->user;
        if ($person !== null) {
            $this->events->dispatch(new IntrospectionAnswered(
                $context->receivedAt,
                $tenant,
                $caller->registration->clientId,
                $person->subject,
                $context,
            ));
        }

        return $response;
    }

    /**
     * RFC 7662 §2.2, §4
     */
    private function tokenOfTheCaller(Tenant $tenant, Client $caller, string $token, RequestContext $context): ?InspectedAccessToken
    {
        try {
            $inspected = $this->tokens->inspect($tenant, $token, $context->receivedAt);
        } catch (InvalidTokenException) {
            return null;
        }

        return $inspected->token->client->equals($caller) ? $inspected : null;
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
