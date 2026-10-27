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
 * The token endpoint (RFC 6749 §3.2, architecture §4.5): the client first, then what the request proved
 * it holds, then the grant type, then the grant. Errors are the ones of §5.2, never a redirect.
 *
 * A request that carries a proof of possession (RFC 9449 §5) binds the tokens of the response to the key
 * it proved, exactly as a certificate binds them to itself; what the grant does with that binding, and
 * whether the authorization it spends was reserved for that key, is the grant's.
 *
 * Which grant serves a request is the wiring's answer and not this endpoint's: the name the request
 * wrote is looked up among the wired grants, and one that names none is "unsupported_grant_type"
 * whatever it says.
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
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake (RFC 8705 §2)
     * @param string|null $dpopProof the DPoP header of the request, null when it carries none (RFC 9449 §4.1)
     *
     * @throws OAuth2Exception
     * @throws ClientKeysUnavailableException when the keys of the client its ID token is encrypted to cannot be read, before anything the request presented is spent
     * @throws KmsUnavailableException when the KMS does not answer to open a key the response is signed with, which a grant somebody signed in for opens before anything the request presented is spent
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): TokenResponse {
        // RFC 6749 §3.2: the token endpoint takes a POST and nothing else, which is what a proof made
        // for this request names in its "htm"
        $endpoint = $this->endpoints->locate($tenant)->token;
        $client = $this->clients
            ->authenticate($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate)
            ->alsoProving($this->proofs->verify($dpopProof, 'POST', $endpoint, $context->receivedAt));
        // FAPI 2.0 Security Profile §5.3.1: bearer tokens are not what this client registered for, and a
        // request that proved nothing is refused here rather than answered with them (RFC 9449 §5,
        // RFC 8705 §3). The error is the one of RFC 6749 §5.2 that says the request is the problem.
        if (! $client->provesWhatItsClientRequires()) {
            throw new InvalidRequestException('The tokens of this client are bound to what the request proves it holds, and this request proves neither a certificate nor a key (FAPI 2.0 Security Profile section 5.3.1).');
        }
        // RFC 8705 §3.4, FAPI 1.0 Advanced Final §5.2.2: this client registered that its tokens are
        // bound to the certificate it presents, whichever way it authenticated, and a request proving
        // no certificate would be answered with tokens bound to nothing. The refusal is here and not in
        // a grant, so that what a request holds is read before the state of whatever it comes to spend:
        // a request that proves nothing is refused rather than told to come back later.
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
        // RFC 6749 §2.1: a public client cannot authenticate, and a grant served only to a client that does
        // is refused here, before it reads anything of the request, as such a registration is refused where
        // a registration meets the wiring
        if ($grant instanceof RequiresClientAuthenticationInterface && $client->client->registration->isPublic()) {
            throw new InvalidClientException('This grant type requires client authentication, and the client authenticated as a public client (RFC 6749 section 2.1).');
        }

        return $grant->grant($client, $request, $context)->toResponse();
    }
}
