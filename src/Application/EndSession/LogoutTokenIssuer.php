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
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * Back-Channel Logout 1.0 §2.4
 */
final readonly class LogoutTokenIssuer
{
    public function __construct(
        private JwsSignerInterface $signer,
        private SubjectIdentifierResolverInterface $subjects,
        private SignatureAlgorithmsInterface $algorithms,
        private UuidGeneratorInterface $uuids,
        private LogoutTokenDeliveryInterface $delivery,
    ) {
    }

    public function issue(Client $client, AuthenticationSession $session, DateTimeImmutable $now): string
    {
        $token = new LogoutToken(
            $session->tenant->issuer,
            $client->registration->clientId,
            $this->subjects->resolve($session->user, $client),
            $session->id,
            $this->uuids->opaque(),
            $now,
            $now->add($this->delivery->deliveryBudget()),
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
