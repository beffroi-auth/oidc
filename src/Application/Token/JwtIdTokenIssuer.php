<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenHash;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §2, §3.1.3.6 (architecture §4.6): the ID token is a JWT signed with the active key of the
 * tenant, in the algorithm the client registered for it, "kid" in the header. Its claims: "iss", "sub",
 * "aud" and "azp" (the client identifier, the only audience), "exp", "iat", "auth_time", "nonce" when
 * the tokens answer an authorization code, "acr", "amr", "at_hash" of the access token of the same
 * response, "sid" of the session. "acr" is always there: the class of the session as it stood when the user
 * authorized, which is what §5.5.1.1 asks for when the request carried "acr_values" and what the request
 * asked for is either that class or one the provider cannot provide. The claims asked for in "claims.id_token"
 * (§5.5) are added from the claims provider; the ones the scopes stand for are not, they belong to
 * UserInfo when an access token is issued (§5.4).
 *
 * The protocol claims win over anything a provider returns under the same name. No "typ" header: the
 * specification defines none for an ID token, and a resource server that requires "at+jwt" (RFC 9068
 * §4) refuses it, which is the point.
 */
final readonly class JwtIdTokenIssuer implements IdTokenIssuerInterface
{
    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string
    {
        $algorithm = $authorization->client->idTokenSignedResponseAlg;
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'sub' => $this->subjects->resolve($authorization->user, $authorization->client)
                ->value,
            'aud' => $authorization->client->clientId,
            'exp' => $now->add($this->lifetime)
                ->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'auth_time' => $authorization->authenticatedAt->getTimestamp(),
        ];
        if ($authorization->nonce !== null) {
            $claims['nonce'] = $authorization->nonce;
        }
        $claims['acr'] = $authorization->authenticationContextClass;
        $claims['amr'] = $authorization->authenticationMethods;
        $claims['azp'] = $authorization->client->clientId;
        $claims['at_hash'] = TokenHash::of($accessToken->value, $algorithm);
        $claims['sid'] = $authorization->session->id->toRfc4122();

        $requested = $authorization->claimsRequest === null ? [] : $authorization->claimsRequest->idToken;
        if ($requested !== []) {
            $claims += $this->claims->claims($authorization->user, [], $requested);
        }

        return $this->signer->sign($authorization->tenant, $algorithm, JwtPayload::encode($claims));
    }
}
