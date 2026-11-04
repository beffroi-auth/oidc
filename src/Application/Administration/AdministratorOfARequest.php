<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Application\Token\PresentedAccessTokenParser;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ProvenPossession;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\TokenBindingNotProvenException;
use Beffroi\Oidc\Port\AdministrationResourceInterface;
use function rtrim;
use SensitiveParameter;

/**
 * Who a request to the administration API of a tenant comes from (decision 0038). It is asked of every request the API
 * receives, before anything is read and the same way whatever the request names: an access token of this provider,
 * addressed to that API (RFC 8707 §2, "aud"), presented with the proof of the key it is bound to (RFC 9449 §7.1) or
 * over a connection that presented the certificate it is bound to (RFC 8705 §3), descending from a session that has
 * not ended and whose proofs satisfy phishing_resistant, issued to a person who administers the tenant now.
 *
 * The issuance of the token held it to all of this already (`AdministrationAudience`). It is asked again here because
 * a token outlives what it was issued on: the person may have left the group since, and a token whose binding is not
 * proven again opens nothing whoever holds it. A token bound to nothing is refused, a bearer token for the API being
 * what decision 0038 excludes; so is a token somebody holds on behalf of its person (RFC 8693 §4.1), which is not the
 * person administering.
 *
 * Every refusal is a refusal of the token, under the scheme it was presented under (RFC 9449 §7.2): a request learns
 * nothing of a resource before it is let in, and what it is told is what it would be told at any other path.
 */
final readonly class AdministratorOfARequest
{
    public function __construct(
        private AdministrationResourceInterface $resources,
        private Administrators $administrators,
        private PresentedAccessTokenParser $presentedTokens,
        private DpopProofVerifier $proofs,
        private AccessTokenInspector $tokens,
        private AuthenticationSessionRepositoryInterface $sessions,
    ) {
    }

    /**
     * @param string                 $method      the method of the request, which its proof names (RFC 9449 §4.2, "htm")
     * @param string                 $path        the path of the request below the identifier of the API, "/tenant" for
     *                                            instance: the proof names the identifier followed by it ("htu")
     * @param string|null            $authorizationHeader the Authorization header of the request, null when it carries none
     * @param ClientCertificate|null $certificate the certificate the caller presented at the TLS handshake (RFC 8705 §3)
     * @param string|null            $dpopProof   the DPoP header of the request, null when it carries none (RFC 9449 §4.1)
     *
     * @throws MissingBearerTokenException when the request presents no token
     * @throws OAuth2Exception             invalid_request, invalid_token or invalid_dpop_proof, or use_dpop_nonce when
     *                                     the proof must be made again with the nonce handed out
     */
    public function administratorOf(
        Tenant $tenant,
        string $method,
        string $path,
        #[SensitiveParameter]
        ?string $authorizationHeader,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): ActingAdministrator {
        $presented = $this->presentedTokens->parse($authorizationHeader, RequestParameters::of([]));
        if ($presented === null) {
            throw new MissingBearerTokenException();
        }
        $api = $this->resources->administrationResourceOf($tenant);
        if ($api === null) {
            throw new InvalidTokenException('The deployment of this tenant names no administration API, so no token opens it.', null, $presented->scheme);
        }
        $provenKey = $this->proofs->verify($dpopProof, $method, rtrim($api->value, '/') . $path, $context->receivedAt, $presented->value);
        try {
            $inspected = $this->tokens->inspect($tenant, $presented->value, $context->receivedAt);
        } catch (InvalidTokenException $exception) {
            throw $exception->presentedUnder($presented->scheme);
        }
        $token = $inspected->token;
        $confirmation = $token->confirmation;
        if ($confirmation === null) {
            throw new InvalidTokenException(
                'The access token is bound to no key, and a token for the administration API always is (RFC 9449 section 6).',
                null,
                $presented->scheme,
            );
        }
        if (! $presented->isPresentedAs($confirmation)) {
            throw new TokenBindingNotProvenException(
                'The access token is bound to a key and was presented as a bearer token (RFC 9449 section 7.1).',
                $confirmation,
            );
        }
        $proven = ProvenPossession::of([$certificate === null ? null : CertificateConfirmation::ofCertificate($certificate), $provenKey]);
        if (! $proven->proves($confirmation)) {
            throw new TokenBindingNotProvenException(
                'The access token is bound to something this request did not present again (RFC 8705 section 3, RFC 9449 section 7.1).',
                $confirmation,
            );
        }
        if (! $token->audience->has($api->value)) {
            throw new InvalidTokenException('The access token is not addressed to the administration API (RFC 8707 section 2).', null, $presented->scheme);
        }
        $user = $inspected->user;
        $signIn = $token->signIn;
        if ($user === null || $signIn === null || $token->actor !== null) {
            throw new InvalidTokenException('The access token was not issued to a person who signed in at this provider.', null, $presented->scheme);
        }
        $session = $this->sessions->find($signIn->sessionId);
        if ($session === null || ! $session->satisfies(AuthenticationContextClass::phishingResistant())) {
            throw new InvalidTokenException(
                'The access token descends from a session whose proofs do not satisfy phishing_resistant.',
                null,
                $presented->scheme,
            );
        }
        if (! $this->administrators->include($user)) {
            throw new InvalidTokenException('The person the access token was issued to does not administer the tenant.', null, $presented->scheme);
        }

        return new ActingAdministrator($tenant, $user, $token->client->registration->clientId, $signIn->sessionId);
    }
}
