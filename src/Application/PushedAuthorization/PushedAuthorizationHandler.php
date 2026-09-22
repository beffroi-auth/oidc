<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\PushedAuthorization;

use DateInterval;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Heidi\Oidc\Application\Authorization\RequestObjectResolver;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Dpop\DpopProofVerifier;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRequest;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;
use function is_string;
use Psr\Clock\ClockInterface;

/**
 * The pushed authorization request endpoint (RFC 9126 §2): the client first, authenticated exactly as at
 * the token endpoint, then the request, read by the very parser the authorization endpoint reads with,
 * so that what is refused there is refused here and nothing is judged twice by two pieces of code.
 * Errors are the ones of RFC 6749 §5.2, never a redirect and never a page (§2.3), which is the caller's
 * to shape; the redirect URI is checked here all the same, because the request is complete.
 *
 * A proof of possession sent here names the key the client will come back with (RFC 9449 §10.1): the
 * provider writes it into the request as the "dpop_jkt" the client could have written itself, and the
 * code that comes out of the request is reserved for that key. A request that names one and is pushed
 * with a proof of another key names two keys, and is refused rather than arbitrated.
 *
 * What comes back is a reference and its lifetime. The parameters kept are the ones the client wrote,
 * credentials taken out: they authenticate the request that carried them and have no business in a store
 * that outlives it. A request the client signed is read here too (RFC 9101 §6.1) and what is kept is
 * what it carried, so that an object is verified by the endpoint it was sent to and once.
 */
final readonly class PushedAuthorizationHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private DpopProofVerifier $proofs,
        private EndpointLocatorInterface $endpoints,
        private AuthorizationRequestParser $parser,
        private RequestObjectResolver $requestObjects,
        private PushedAuthorizationRequestRepositoryInterface $requests,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT60S'),
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake (RFC 8705 §2)
     * @param string|null $dpopProof the DPoP header of the request, null when it carries none (RFC 9449 §4.1)
     *
     * @throws OAuth2Exception
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): PushedAuthorizationResponse {
        // RFC 9126 §2: a request is pushed with a POST, which is what a proof made for it names
        $endpoint = $this->endpoints->locate($tenant)->pushedAuthorizationRequest;
        $client = $this->clients->authenticate($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate)->client;
        $provenKey = $this->proofs->verify($dpopProof, 'POST', $endpoint, $context->receivedAt);
        if (RequestParameters::isPresent($parameters, 'request_uri')) {
            throw new InvalidRequestException('The request_uri parameter is not one of those a pushed authorization request carries (RFC 9126 section 2.1).');
        }

        // RFC 9126 §2.1: the request names the authenticated client and no other. A "client_id" of the
        // body that named another was already refused by the authenticator, and a client that
        // authenticated through the Authorization header carries none, so the authenticated client is
        // what the parser is given to read.
        $parameters['client_id'] = $client->clientId;
        // RFC 9101 §6.1: a pushed request may itself be a request object, which FAPI 2.0 Message
        // Signing asks of one. It is read here, against the client that has just authenticated, and
        // what the store keeps is the request it carried: the object is verified once, by the endpoint
        // the client sent it to, and the authorization endpoint reads parameters like any other.
        $parameters = $this->requestObjects->resolve($tenant, $parameters, $client) ?? $parameters;
        $parameters = self::reservedFor($parameters, $provenKey);
        $target = $this->parser->redirectTarget($tenant, $parameters, true);
        $this->parser->parse($target, $parameters);

        $now = $this->clock->now();
        $requestUri = RequestUri::generate();
        $request = new PushedAuthorizationRequest($requestUri->hash(), $client, self::kept($parameters), $now, $now->add($this->lifetime));
        $this->requests->save($request);

        return new PushedAuthorizationResponse($requestUri, $request->expiresIn($now));
    }

    /**
     * RFC 9449 §10.1: the key of the proof is the key the request reserves its code for, whether the
     * client wrote the "dpop_jkt" itself or let the proof say it. Both are read as the parser reads any
     * parameter, so a thumbprint of the wrong shape is refused there and once.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws InvalidRequestException when the request names one key and the proof another
     *
     * @return array<string, mixed>
     */
    private static function reservedFor(array $parameters, ?KeyConfirmation $provenKey): array
    {
        if ($provenKey === null) {
            return $parameters;
        }
        $named = $parameters['dpop_jkt'] ?? null;
        if (is_string($named) && $named !== '' && $named !== $provenKey->thumbprint) {
            throw new InvalidRequestException('The dpop_jkt of the pushed request names another key than the proof that carried it (RFC 9449 section 10.1).');
        }
        $parameters['dpop_jkt'] = $provenKey->thumbprint;

        return $parameters;
    }

    /**
     * What the store keeps of the body: the parameters of an authorization request as the client wrote
     * them, without what authenticated it (RFC 9126 §2.1) and without what is not a form parameter at
     * all, which the parser has already refused for every name it reads.
     *
     * @param array<string, mixed> $parameters
     *
     * @return array<string, string>
     */
    private static function kept(array $parameters): array
    {
        $kept = [];
        foreach (ClientAuthenticationRequest::withoutCredentials($parameters) as $name => $value) {
            if (is_string($value)) {
                $kept[$name] = $value;
            }
        }

        return $kept;
    }
}
