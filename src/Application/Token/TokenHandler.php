<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientAuthenticator;
use Heidi\Oidc\Application\Dpop\DpopProofVerifier;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnauthorizedClientException;
use Heidi\Oidc\Exception\UnsupportedGrantTypeException;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use function sprintf;

/**
 * The token endpoint (RFC 6749 §3.2, architecture §4.5): the client first, then what the request proved
 * it holds, then the grant type, then the grant. Errors are the ones of §5.2, never a redirect.
 *
 * A request that carries a proof of possession (RFC 9449 §5) binds the tokens of the response to the key
 * it proved, exactly as a certificate binds them to itself; what the grant does with that binding, and
 * whether the authorization it spends was reserved for that key, is the grant's.
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
        private DpopProofVerifier $proofs,
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
        $request = new TokenRequest($parameters);

        $grantType = GrantType::tryFrom($request->required('grant_type'));
        $grant = $grantType === null ? null : $this->grants[$grantType->value] ?? null;
        if ($grantType === null || $grant === null) {
            throw new UnsupportedGrantTypeException('The grant type is not supported by this provider.');
        }
        if (! $client->client->registration->allowsGrant($grantType)) {
            throw new UnauthorizedClientException('The client is not registered for this grant type.');
        }

        return $grant->grant($client, $request, $context)->toResponse();
    }
}
