<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Administration\AdministrationAudience;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use DateTimeImmutable;

/**
 * The access tokens of every grant, held to the reservation of the administration API when they are minted (decision
 * 0038): the issuer the provider is wired with mints them, and none is minted for that API that its reservation does not
 * allow, whichever grant asked. The grants know nothing of it, so a grant added later is held to it as well.
 */
final readonly class AdministrationAudienceGuard implements AccessTokenIssuerInterface
{
    public function __construct(
        private AccessTokenIssuerInterface $issuer,
        private AdministrationAudience $administration,
    ) {
    }

    public function address(Client $client): AddressedAccessToken
    {
        return $this->issuer->address($client);
    }

    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
    {
        return $this->issuer->addressFor($authorization);
    }

    /**
     * @throws InvalidTargetException when the token would be addressed to the administration API of its tenant and its authorization holds to less than the reservation
     * @throws InvalidGrantException  when the token would be addressed to that API and the session it descends from has ended or expired
     */
    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $this->administration->assertMayBeAddressedBy($authorization, $now);

        return $this->issuer->issue($authorization, $addressed, $now);
    }
}
