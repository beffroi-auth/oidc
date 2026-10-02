<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Port\UuidGeneratorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\JwsSignerInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\EndSession\LogoutToken;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * Mints the logout token of one client of one ended session (Back-Channel Logout 1.0 §2.4, architecture
 * §4.9), signed by the active key of the tenant in the algorithm the client registered for its ID
 * tokens, since that is the one it knows how to verify (§2.6). The "sub" is the one the client already
 * sees (OIDC Core §8), never the internal identifier.
 */
final readonly class LogoutTokenIssuer
{
    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        private UuidGeneratorInterface $uuids,
    ) {
    }

    /**
     * @return string the compact JWS
     */
    public function issue(Client $client, AuthenticationSession $session, DateTimeImmutable $now): string
    {
        $token = new LogoutToken(
            $session->tenant->issuer,
            $client->registration->clientId,
            $this->subjects->resolve($session->user, $client),
            $session->id,
            $this->uuids->opaque(),
            $now,
        );

        return $this->signer->sign(
            $session->tenant,
            $client->registration->idToken->signature ?? $this->algorithms->defaultAlgorithm(),
            JwtPayload::encode($token->claims()),
            [
                'typ' => LogoutToken::TYPE,
            ],
        );
    }
}
