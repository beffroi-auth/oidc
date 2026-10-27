<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Domain\Token\TokenHash;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §2, §3.1.3.6 (architecture §4.6): signed in the algorithm the client registered for, or in the
 * one the provider signs with by default when it registered none (OIDC Registration §2), "acr"
 * always present, "at_hash" of the access token of the same response, the "claims.id_token" of §5.5 added
 * from the claims provider. The protocol claims win over a provider's. No "typ" header: a resource server
 * requiring "at+jwt" refuses it, which is the point.
 *
 * "sid" names the session the token was issued in, in every ID token and for every client: an OP that
 * announces frontchannel_logout_session_supported or backchannel_logout_session_supported includes it in
 * the ID tokens it issues (Front-Channel Logout 1.0 §3, Back-Channel Logout 1.0 §2.1), and it is what
 * the logout endpoint reads back from an id_token_hint to know the hint describes the session in front
 * of it (architecture §4.9). What a client registers, frontchannel_logout_session_required and
 * backchannel_logout_session_required, says whether "iss" and "sid" go on its logout URI and in its
 * logout token, not whether they go in its ID token.
 *
 * A client that registered an encryption receives the signed token inside a JWE addressed to one of its
 * keys (§3.1.3.7), which is the same two steps as for the UserInfo answer and the signed authorization
 * response and is written once, in ClientDocumentIssuer. The key is read when the token is addressed, which
 * the grant does before it spends anything, and the token is struck for the key that was read.
 */
final readonly class JwtIdTokenIssuer implements IdTokenIssuerInterface
{
    public function __construct(
        private ClientDocumentIssuer $documents,
        private SubjectIdentifierResolverInterface $subjects,
        private ClaimsProviderInterface $claims,
        private SignatureAlgorithmsInterface $algorithms,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function address(Client $client): AddressedFormat
    {
        return $this->documents->address($client, $client->registration->idToken);
    }

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedFormat $addressed, DateTimeImmutable $now): string
    {
        $algorithm = $addressed->format->signature ?? $this->algorithms->defaultAlgorithm();
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'sub' => $this->subjects->resolve($authorization->user, $authorization->client)->value,
            'aud' => $authorization->client->registration->clientId,
            'exp' => $now->add($this->lifetime)->getTimestamp(),
            'iat' => $now->getTimestamp(),
            'auth_time' => $authorization->authentication->authenticatedAt->getTimestamp(),
        ];
        if ($authorization->nonce !== null) {
            $claims['nonce'] = $authorization->nonce;
        }
        $claims['acr'] = $authorization->authentication->contextClass;
        $claims['amr'] = $authorization->authentication->methods;
        $claims['azp'] = $authorization->client->registration->clientId;
        $claims['at_hash'] = TokenHash::of($accessToken->value, $algorithm);
        $claims['sid'] = $authorization->session->id->toRfc4122();

        $requested = $authorization->claimsRequest->idToken ?? [];
        if ($requested !== []) {
            $claims += $this->claims->claims($authorization->user, null, $requested);
        }

        return $this->documents->issue($authorization->client, $addressed, $claims);
    }
}
