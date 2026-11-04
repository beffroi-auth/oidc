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
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\UserInfoAnswered;
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
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * OIDC Core §5.3, RFC 6750 §3.1, RFC 9449 §7.1, §7.2
 *
 * A token asked for a resource (RFC 8707 §2) is addressed to it, not to this endpoint, and is refused here.
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
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the request body, never the query string (RFC 6750 §2.3)
     *
     * @throws MissingBearerTokenException
     * @throws OAuth2Exception
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
        try {
            $inspected = $this->tokens->inspect($tenant, $presented->value, $context->receivedAt);
        } catch (InvalidTokenException $exception) {
            throw $exception->presentedUnder($presented->scheme);
        }
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
            throw InvalidTokenException::addressedElsewhere($presented->scheme);
        }
        $user = $inspected->user;
        if ($user === null || $token->scopes?->has(Scope::openid()) !== true) {
            throw new InsufficientScopeException(
                'The access token was not obtained through an OpenID Connect authentication request.',
                new Scopes([Scope::openid()]),
                $presented->scheme,
            );
        }

        $requested = array_fill_keys($token->userinfoClaims, new ClaimRequest());
        $client = $token->client;
        $subject = $this->subjects->resolve($user, $client)->value;
        $claims = UserInfoResponse::claimsOf($subject, $this->claims->claims($user, $token->scopes, $requested));
        $response = $this->answer($tenant, $client, $subject, $claims);
        // Dispatched once the answer exists: the journal records what was served, never what was attempted.
        $this->events->dispatch(new UserInfoAnswered(
            $context->receivedAt,
            $tenant,
            $client->registration->clientId,
            $user->subject,
            $context,
        ));

        return $response;
    }

    /**
     * OIDC Core §5.3.2
     *
     * @param array<string, mixed> $claims
     */
    private function answer(Tenant $tenant, Client $client, string $subject, array $claims): UserInfoResponse
    {
        $format = $client->registration->userInfo;
        if ($format->isPlain()) {
            return UserInfoResponse::json($subject, $claims);
        }
        $claims += [
            'iss' => (string) $tenant->issuer,
            'aud' => $client->registration->clientId,
        ];

        return UserInfoResponse::jwt($subject, $claims, $this->documents->issue($client, $this->documents->address($client, $format), $claims));
    }
}
