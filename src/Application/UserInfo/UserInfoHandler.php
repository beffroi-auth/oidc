<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\UserInfo;

use function array_fill_keys;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\PresentedAccessTokenParser;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ProvenPossession;
use Beffroi\Oidc\Domain\UserInfo\UserInfoResponse;
use Beffroi\Oidc\Exception\InsufficientScopeException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\TokenBindingNotProvenException;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * The UserInfo endpoint (OIDC Core §5.3, architecture §4.7): an access token (RFC 6750 §2, RFC 9449 §7.1)
 * inspected as an access token of the provider, answered with the claims its scopes stand for (§5.4) and
 * those asked for by name (§5.5). A token without "openid" is insufficient_scope (§5.3.1). Errors are the
 * ones of RFC 6750 §3.1 and of RFC 9449 §7.1.
 *
 * It answers for a user, so a token nobody signed in for opens nothing here: a client acting for itself
 * (RFC 6749 §4.4) asks its token for a resource and is refused by the rule below that the token must be
 * addressed to this provider, and a token with nobody behind it that got that far would be refused for
 * carrying no "openid" either (OIDC Core §5.3.1). The claims of a user are served to a token that names one
 * and to no other, whatever else the request is right about.
 *
 * It is a token of the provider itself: a token asked for a resource (RFC 8707 §2) is addressed to that
 * resource, and this endpoint is not it, so it is refused here however valid it is elsewhere. A client
 * that comes for the claims of its user asks for a token naming no resource, which is what a client of
 * OpenID Connect sends and what every certification profile plays.
 *
 * This is a protected resource of the provider, and the first one: a bound token (RFC 8705 §3,
 * RFC 9449 §6.1) is honoured here only when the request proves again what it is bound to, the
 * certificate of its connection or the key of the proof it carries, and refused with invalid_token when
 * it proves another or nothing. A token bound to a key is refused as soon as it is presented as a bearer
 * token, before anything of it is read: the scheme is part of how it is presented (RFC 9449 §7.1).
 * Whoever steals a bound token holds bytes that open nothing.
 *
 * The answer is the plain JSON unless the client registered a signature or an encryption for it (§5.3.2),
 * in which case it is a JWT carrying the same claims plus the "iss" and the "aud" that tell a client who
 * wrote them and for whom. Signed then encrypted, as an ID token is and in the same place.
 */
final readonly class UserInfoHandler
{
    public function __construct(
        private AccessTokenInspector $tokens,
        private ClientDocumentIssuer $documents,
        private DpopProofVerifier $proofs,
        private EndpointLocatorInterface $endpoints,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
        private PresentedAccessTokenParser $presentedTokens,
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
    public function handle(
        Tenant $tenant,
        string $method,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): UserInfoResponse {
        $presented = $this->presentedTokens->parse($authorizationHeader, RequestParameters::of($parameters));
        if ($presented === null) {
            throw new MissingBearerTokenException();
        }
        $provenKey = $this->proofs->verify($dpopProof, $method, $this->endpoints->locate($tenant)->userinfo, $context->receivedAt, $presented->value);
        $inspected = $this->tokens->inspect($tenant, $presented->value, $context->receivedAt);
        $token = $inspected->token;
        $confirmation = $token->confirmation;
        if ($confirmation !== null && ! $presented->isPresentedAs($confirmation)) {
            throw new TokenBindingNotProvenException(
                'The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1).',
                $confirmation,
            );
        }
        $proven = ProvenPossession::of([$certificate === null ? null : CertificateConfirmation::ofCertificate($certificate), $provenKey]);
        if ($confirmation !== null && ! $proven->proves($confirmation)) {
            throw new TokenBindingNotProvenException(
                'The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).',
                $confirmation,
            );
        }
        if (! $token->audience->has($token->client->registration->clientId)) {
            throw InvalidTokenException::addressedElsewhere();
        }
        $user = $inspected->user;
        if ($user === null || $token->scopes?->has(Scope::openid()) !== true) {
            throw new InsufficientScopeException(
                'The access token was not obtained through an OpenID Connect authentication request.',
                new Scopes([Scope::openid()]),
            );
        }

        $requested = array_fill_keys($token->userinfoClaims, new ClaimRequest());
        $client = $token->client;
        $subject = $this->subjects->resolve($user, $client)->value;
        $claims = UserInfoResponse::claimsOf($subject, $this->claims->claims($user, $token->scopes, $requested));
        $format = $client->registration->userInfo;
        if ($format->isPlain()) {
            return UserInfoResponse::json($subject, $claims);
        }
        // OIDC Core §5.3.2: a JWT answer names who wrote it and for whom, which the JSON one has no room to say.
        $claims += [
            'iss' => (string) $tenant->issuer,
            'aud' => $client->registration->clientId,
        ];

        return UserInfoResponse::jwt($subject, $claims, $this->documents->issue($client, $format, $claims));
    }
}
