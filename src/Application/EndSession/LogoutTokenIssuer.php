<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\UuidGeneratorInterface;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\EndSession\LogoutToken;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * Back-Channel Logout 1.0 §2.4
 *
 * Always signed, and encrypted when the client encrypts its ID tokens.
 */
final readonly class LogoutTokenIssuer
{
    public function __construct(
        private ClientDocumentIssuer $documents,
        private SubjectIdentifierResolverInterface $subjects,
        private UuidGeneratorInterface $uuids,
        private LogoutTokenDeliveryInterface $delivery,
    ) {
    }

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws ClientKeysUnavailableException when the client encrypts its ID tokens and publishes no key that can be read for it
     */
    public function issue(Client $client, AuthenticationSession $session, DateTimeImmutable $now): string
    {
        $idToken = $client->registration->idToken;
        $addressed = $this->documents->address($client, ResponseFormat::signed($idToken->signature, $idToken->encryption));
        $token = new LogoutToken(
            $session->tenant->issuer,
            $client->registration->clientId,
            $this->subjects->resolve($session->user, $client),
            $session->id,
            $this->uuids->opaque(),
            $now,
            $now->add($this->delivery->deliveryBudget()),
        );

        return $this->documents->issue(
            $client,
            $addressed,
            $token->claims(),
            [
                'typ' => LogoutToken::TYPE,
            ],
            [
                'iss' => (string) $token->issuer,
            ],
        );
    }
}
