<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\UserInfo;

use function array_fill_keys;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Dpop\DpopProofVerifier;
use Heidi\Oidc\Application\Token\AccessTokenInspector;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\CertificateConfirmation;
use Heidi\Oidc\Domain\Token\PresentedAccessToken;
use Heidi\Oidc\Domain\Token\ProvenPossession;
use Heidi\Oidc\Domain\UserInfo\UserInfoResponse;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\TokenBindingNotProvenException;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\EndpointLocatorInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * The UserInfo endpoint (OIDC Core §5.3, architecture §4.7): an access token (RFC 6750 §2, RFC 9449 §7.1)
 * inspected as an access token of the provider, answered with the claims its scopes stand for (§5.4) and
 * those asked for by name (§5.5). A token without "openid" is insufficient_scope (§5.3.1). Errors are the
 * ones of RFC 6750 §3.1 and of RFC 9449 §7.1.
 *
 * This is a protected resource of the provider, and the first one: a bound token (RFC 8705 §3,
 * RFC 9449 §6.1) is honoured here only when the request proves again what it is bound to, the
 * certificate of its connection or the key of the proof it carries, and refused with invalid_token when
 * it proves another or nothing. A token bound to a key is refused as soon as it is presented as a bearer
 * token, before anything of it is read: the scheme is part of how it is presented (RFC 9449 §7.1).
 * Whoever steals a bound token holds bytes that open nothing.
 */
final readonly class UserInfoHandler
{
    public function __construct(
        private AccessTokenInspector $tokens,
        private DpopProofVerifier $proofs,
        private EndpointLocatorInterface $endpoints,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
    ) {
    }

    /**
     * @param string $method the method of the request, which a proof made for it names (RFC 9449 §4.2)
     * @param array<string, mixed> $parameters the form parameters of the request body, never the query string (RFC 6750 §2.3)
     * @param ClientCertificate|null $certificate the certificate the caller presented at the TLS handshake (RFC 8705 §3)
     * @param string|null $dpopProof the DPoP header of the request, null when it carries none (RFC 9449 §4.1)
     *
     * @throws MissingBearerTokenException 401 with a bare challenge
     * @throws OAuth2Exception invalid_request, invalid_token, invalid_dpop_proof or insufficient_scope
     */
    public function handle(Tenant $tenant, string $method, ?string $authorizationHeader, array $parameters, RequestContext $context, ?ClientCertificate $certificate = null, ?string $dpopProof = null): UserInfoResponse
    {
        $presented = PresentedAccessToken::fromRequest($authorizationHeader, $parameters);
        if ($presented === null) {
            throw new MissingBearerTokenException();
        }
        $provenKey = $this->proofs->verify($dpopProof, $method, $this->endpoints->locate($tenant)->userinfo, $context->receivedAt, $presented->value);
        $inspected = $this->tokens->inspect($tenant, $presented->value, $context->receivedAt);
        $token = $inspected->token;
        $confirmation = $token->confirmation;
        if ($confirmation !== null && ! $presented->isPresentedAs($confirmation)) {
            throw new TokenBindingNotProvenException('The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1).', $confirmation);
        }
        $proven = ProvenPossession::of([$certificate === null ? null : CertificateConfirmation::ofCertificate($certificate), $provenKey]);
        if ($confirmation !== null && ! $proven->proves($confirmation)) {
            throw new TokenBindingNotProvenException('The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).', $confirmation);
        }
        if (! $token->hasScope(Scope::openid())) {
            throw new InsufficientScopeException('The access token was not obtained through an OpenID Connect authentication request.', [Scope::openid()]);
        }
        $user = $inspected->user;

        $requested = array_fill_keys($token->userinfoClaims, new ClaimRequest());

        return new UserInfoResponse(
            $this->subjects->resolve($user, $token->client)
                ->value,
            $this->claims->claims($user, $token->scopes, $requested),
        );
    }
}
