<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use function implode;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 9068 (architecture §4.6): "typ" is "at+jwt" (§2.1), the claims are those of §2.2 and §2.2.1, "scope"
 * in the syntax of RFC 8693 §4.2, "aud" the client identifier. Two private claims (RFC 7519 §4.3): "grant_id"
 * names the code the token descends from, "userinfo_claims" what the client asked for by name (OIDC Core §5.5).
 * Nothing is stored: the token is its own record. An access token is read by resource servers, not by the
 * client, so it is signed with the algorithm the provider signs with by default, never the one the client
 * registered for its ID tokens. A token issued on a request that proved a key carries the "cnf" of
 * RFC 7800 §3.1, which is what binds it to that key (RFC 8705 §3).
 */
final readonly class JwtAccessTokenIssuer implements AccessTokenIssuerInterface
{
    public const string TYPE = 'at+jwt';

    public const string USERINFO_CLAIMS = 'userinfo_claims';

    public const string GRANT_ID = 'grant_id';

    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'exp' => $expiresAt->getTimestamp(),
            'aud' => $authorization->client->clientId,
            'sub' => $this->subjects->resolve($authorization->user, $authorization->client)->value,
            'client_id' => $authorization->client->clientId,
            'iat' => $now->getTimestamp(),
            'jti' => Uuid::v4()->toRfc4122(),
            ...$authorization->authentication->toClaims(),
        ];
        $claims['scope'] = implode(' ', $authorization->scopes);
        $requested = $authorization->claimsRequest === null ? [] : $authorization->claimsRequest->userinfo;
        if ($requested !== []) {
            $claims[self::USERINFO_CLAIMS] = array_keys($requested);
        }
        $claims['sid'] = $authorization->session->id->toRfc4122();
        $claims[self::GRANT_ID] = $authorization->grantId->toRfc4122();
        // RFC 8705 §3.1: what the client proved at the request this token answers, so that a resource
        // server verifying the token offline knows what to ask its caller to present again
        $claims = [...$claims, ...($authorization->confirmation?->toClaims() ?? [])];

        $jws = $this->signer->sign($authorization->tenant, $this->algorithms->defaultAlgorithm(), JwtPayload::encode($claims), [
            'typ' => self::TYPE,
        ]);

        return new AccessToken($jws, $now, $expiresAt);
    }
}
