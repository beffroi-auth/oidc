<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use function implode;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 9068 (architecture §4.6): the access token is a JWT signed with the active key of the tenant, its
 * header "typ" set to "at+jwt" (§2.1) so that no other token of this issuer passes for one and it passes
 * for no other. The claims are those of §2.2: "iss", "exp", "aud", "sub", "client_id", "iat", "jti";
 * "auth_time", "acr" and "amr" of §2.2.1 as the authorization recorded them; "scope" of §2.2.3 in the
 * syntax of RFC 8693 §4.2, the scopes of this response. "aud" is the client identifier until a
 * "resource" parameter says otherwise (RFC 8707, later). "sid" names the session the token descends
 * from, which is what a logout revokes, and "grant_id" (a private claim, RFC 7519 §4.3) the authorization
 * code the token descends from, which is what the replay of that code revokes (RFC 6749 §4.1.2): an
 * opaque name, never the hash of the code, which is how a code is looked up.
 *
 * Ten minutes, and nothing stored: the token is its own record. The one who knows the user (a UserInfo
 * endpoint, a resource server) reads it and the JWK Set, and asks nothing else of the provider. That is
 * why the token also carries "userinfo_claims" (a private claim, RFC 7519 §4.3): the names the client
 * asked for by "claims.userinfo" (OIDC Core §5.5), which UserInfo serves on top of the scopes and could
 * not learn otherwise. Absent when nothing was asked; the "id_token" member was answered at issuance.
 */
final readonly class JwtAccessTokenIssuer implements AccessTokenIssuerInterface
{
    public const string TYPE = 'at+jwt';

    public const string USERINFO_CLAIMS = 'userinfo_claims';

    public const string GRANT_ID = 'grant_id';

    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private DateInterval $lifetime = new DateInterval('PT10M'),
        private SignatureAlgorithm $algorithm = SignatureAlgorithm::RS256,
    ) {
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'exp' => $expiresAt->getTimestamp(),
            'aud' => $authorization->client->clientId,
            'sub' => $this->subjects->resolve($authorization->user, $authorization->client)
                ->value,
            'client_id' => $authorization->client->clientId,
            'iat' => $now->getTimestamp(),
            'jti' => Uuid::v4()->toRfc4122(),
            'auth_time' => $authorization->authenticatedAt->getTimestamp(),
            'acr' => $authorization->authenticationContextClass,
            'amr' => $authorization->authenticationMethods,
        ];
        $claims['scope'] = implode(' ', $authorization->scopes);
        $requested = $authorization->claimsRequest === null ? [] : $authorization->claimsRequest->userinfo;
        if ($requested !== []) {
            $claims[self::USERINFO_CLAIMS] = array_keys($requested);
        }
        $claims['sid'] = $authorization->session->id->toRfc4122();
        $claims[self::GRANT_ID] = $authorization->grantId->toRfc4122();

        $jws = $this->signer->sign($authorization->tenant, $this->algorithm, JwtPayload::encode($claims), [
            'typ' => self::TYPE,
        ]);

        return new AccessToken($jws, $now, $expiresAt);
    }
}
