<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenHash;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\IdTokenIssuerInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §2, §3.1.3.6 (architecture §4.6): signed in the algorithm the client registered for, or in the
 * one the provider signs with by default when it registered none (OIDC Registration §2), "acr"
 * always present, "at_hash" of the access token of the same response, the "claims.id_token" of §5.5 added
 * from the claims provider. The protocol claims win over a provider's. No "typ" header: a resource server
 * requiring "at+jwt" refuses it, which is the point.
 */
final readonly class JwtIdTokenIssuer implements IdTokenIssuerInterface
{
    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
        private SignatureAlgorithmsInterface $algorithms,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string
    {
        $algorithm = $authorization->client->idTokenSignedResponseAlg ?? $this->algorithms->defaultAlgorithm();
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'sub' => $this->subjects->resolve($authorization->user, $authorization->client)
                ->value,
            'aud' => $authorization->client->clientId,
            'exp' => $now->add($this->lifetime)
                ->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'auth_time' => $authorization->authentication->authenticatedAt->getTimestamp(),
        ];
        if ($authorization->nonce !== null) {
            $claims['nonce'] = $authorization->nonce;
        }
        $claims['acr'] = $authorization->authentication->contextClass;
        $claims['amr'] = $authorization->authentication->methods;
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
