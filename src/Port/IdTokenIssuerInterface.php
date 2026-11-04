<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedIdToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * OIDC Core §2
 *
 * A grant addresses the token before it spends what the request presented, so that issue() asks nothing of the KMS
 * or of the client.
 */
interface IdTokenIssuerInterface
{
    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws ClientKeysUnavailableException
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function address(Client $client): AddressedIdToken;

    /**
     * @return string the compact JWS, or the compact JWE that carries it
     */
    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedIdToken $addressed, DateTimeImmutable $now): string;
}
