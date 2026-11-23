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
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidTargetException;
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
     * @throws InvalidTargetException when the token is addressed to the administration API and its authorization holds to less than its reservation (decision 0038)
     * @throws InvalidGrantException  when the token is addressed to the administration API and the session it descends from has ended or expired (decision 0038)
     */
    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken;
}
