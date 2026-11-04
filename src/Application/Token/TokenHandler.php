<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Beffroi\Oidc\Exception\UnsupportedGrantTypeException;
use Beffroi\Oidc\Port\EndpointLocatorInterface;

/**
 * RFC 6749 §3.2, §5.2, RFC 9449 §5
 */
final readonly class TokenHandler
{
    public function __construct(
        private ClientAuthenticator $clients,
        private DpopProofVerifier $proofs,
        private EndpointLocatorInterface $endpoints,
        private ServedGrants $grants,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body
     *
     * @throws OAuth2Exception
     * @throws ClientKeysUnavailableException before anything the request presented is spent
     * @throws KmsUnavailableException before anything the request presented is spent
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): TokenResponse {
        $endpoint = $this->endpoints->locate($tenant)->token;
        $client = $this->clients
            ->authenticate($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate)
            ->alsoProving($this->proofs->verify($dpopProof, 'POST', $endpoint, $context->receivedAt));
        if (! $client->provesWhatItsClientRequires()) {
            throw new InvalidRequestException('The tokens of this client are bound to what the request proves it holds, and this request proves neither a certificate nor a key (FAPI 2.0 Security Profile section 5.3.1).');
        }
        // Checked before any grant reads what the request spends, so that a request proving nothing is refused
        // rather than told to come back later.
        if (! $client->provesTheCertificateItsTokensAreBoundTo()) {
            throw new InvalidRequestException('The tokens of this client are bound to the certificate it presents, and this request proves none (RFC 8705 section 3.4).');
        }
        $request = RequestParameters::of($parameters);

        $grant = $this->grants->named($request->required('grant_type'));
        if ($grant === null) {
            throw new UnsupportedGrantTypeException('The grant type is not supported by this provider.');
        }
        if (! $client->client->registration->allowsGrant($grant->grantType())) {
            throw new UnauthorizedClientException('The client is not registered for this grant type.');
        }
        if ($grant instanceof RequiresClientAuthenticationInterface && $client->client->registration->isPublic()) {
            throw new InvalidClientException('This grant type requires client authentication, and the client authenticated as a public client (RFC 6749 section 2.1).');
        }

        return $grant->grant($client, $request, $context)->toResponse();
    }
}
