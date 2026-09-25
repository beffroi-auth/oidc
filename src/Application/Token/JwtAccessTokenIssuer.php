<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Port\UuidGeneratorInterface;
use function array_keys;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\AuthorizationInterface;
use Heidi\Oidc\Domain\Token\ClientSubject;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenSignIn;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * RFC 9068 (architecture §4.6): "typ" is "at+jwt" (§2.1), the claims are those of §2.2 and §2.2.1, "scope"
 * in the syntax of RFC 8693 §4.2, "aud" the resources the request asked the token for (RFC 8707 §2) and
 * the client itself when it asked for none. A token somebody signed in for names them in "sub" and says
 * which sign-in it descends from; a token a client holds for itself names that client (§2.2) and carries
 * no "sid", no "auth_time", no "acr" and no "amr", there being nobody to describe (RFC 6749 §4.4).
 * Which of the two a token is, the authorization says by what it is, never the name of the grant. Two private claims (RFC 7519 §4.3): "grant_id"
 * names the code the token descends from, "userinfo_claims" what the client asked for by name (OIDC Core §5.5).
 * Nothing is stored: the token is its own record. An access token is read by resource servers, not by the
 * client, so it is signed with the algorithm the provider signs with by default, never the one the client
 * registered for its ID tokens. A token issued on a request that proved a key carries the "cnf" of
 * RFC 7800 §3.1, which is what binds it to that key (RFC 8705 §3).
 */
final readonly class JwtAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public const string TYPE = 'at+jwt';

    public const string USERINFO_CLAIMS = 'userinfo_claims';

    public const string GRANT_ID = 'grant_id';

    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        private UuidGeneratorInterface $uuids,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    /**
     * The name a client registers to receive its access tokens in this shape, which JwtAccessTokenVerifier
     * reads them back under.
     */
    public function name(): string
    {
        return 'jwt';
    }

    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $signIn = $authorization instanceof UserAuthorizationInterface
            ? new TokenSignIn($authorization->session->id, $authorization->authentication)
            : null;
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'exp' => $expiresAt->getTimestamp(),
            'aud' => $authorization->audience()->claim(),
            'sub' => $this->subjectOf($authorization)->value,
            'client_id' => $authorization->client->registration->clientId,
            'iat' => $now->getTimestamp(),
            'jti' => $this->uuids->opaque()->toRfc4122(),
            // RFC 9068 §2.2.1: what the session had proven, of a token there is a session behind
            ...($signIn?->authentication->toClaims() ?? []),
        ];
        $claims['scope'] = (string) $authorization->scopes;
        $requested =
            $authorization instanceof UserAuthorizationInterface && $authorization->claimsRequest !== null
                ? $authorization->claimsRequest->userinfo
                : [];
        if ($requested !== []) {
            $claims[self::USERINFO_CLAIMS] = array_keys($requested);
        }
        if ($signIn !== null) {
            $claims['sid'] = $signIn->sessionId->toRfc4122();
        }
        $claims[self::GRANT_ID] = $authorization->grantId->toRfc4122();
        // RFC 8705 §3.1: what the client proved at the request this token answers, so that a resource
        // server verifying the token offline knows what to ask its caller to present again
        $claims = [...$claims, ...($authorization->confirmation?->toClaims() ?? [])];

        $jws = $this->signer->sign($authorization->tenant, $this->algorithms->defaultAlgorithm(), JwtPayload::encode($claims), [
            'typ' => self::TYPE,
        ]);

        return new AccessToken($jws, $now, $expiresAt);
    }

    /**
     * RFC 9068 §2.2: the pairwise subject of whoever signed in (OIDC Core §8), and the client itself when
     * nobody did (RFC 6749 §4.4).
     */
    private function subjectOf(AuthorizationInterface $authorization): Subject
    {
        return $authorization instanceof UserAuthorizationInterface
            ? $this->subjects->resolve($authorization->user, $authorization->client)
            : ClientSubject::of($authorization->client);
    }
}
