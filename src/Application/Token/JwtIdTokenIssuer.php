<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedIdToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Domain\Token\TokenHash;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\IdTokenIssuerInterface;
use Beffroi\Oidc\Port\SubjectIdentifierOpenerInterface;

/**
 * OIDC Core §2, §3.1.3.6
 *
 * The protocol claims win over a provider's. "sid" is in every ID token: the "*_logout_session_required" members of
 * a registration govern only the logout URI and the logout token.
 */
final readonly class JwtIdTokenIssuer implements IdTokenIssuerInterface
{
    public function __construct(
        private ClientDocumentIssuer $documents,
        private SubjectIdentifierOpenerInterface $subjects,
        private ClaimsProviderInterface $claims,
        private SignatureAlgorithmsInterface $algorithms,
        public DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function address(Client $client): AddressedIdToken
    {
        return new AddressedIdToken($this->documents->address($client, $client->registration->idToken), $this->subjects->open($client));
    }

    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedIdToken $addressed, DateTimeImmutable $now): string
    {
        $algorithm = $addressed->format->format->signature ?? $this->algorithms->defaultAlgorithm();
        $claims = [
            'iss' => (string) $authorization->tenant->issuer,
            'sub' => $addressed->subjectIdentifier->subjectOf($authorization->user)->value,
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

        return $this->documents->issue($authorization->client, $addressed->format, $claims);
    }
}
