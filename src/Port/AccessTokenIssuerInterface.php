<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;

/**
 * A grant addresses the token before it spends what the request presented, so that issue() asks nothing of the KMS.
 */
interface AccessTokenIssuerInterface
{
    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function address(Client $client): AddressedAccessToken;

    /**
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken;

    /**
     * @throws LogicException when the token needs something that was not read when it was addressed
     */
    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken;
}
