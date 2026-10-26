<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;

/**
 * Mints the ID token of a response (OIDC Core §2, architecture §4.6); the access token is given for "at_hash".
 *
 * An ID token describes who signed in, so it is issued from an authorization somebody signed in for and
 * from no other: a grant with nobody behind it has none to carry (RFC 6749 §4.4.3).
 *
 * It is addressed before it is struck (OIDC Core §3.1.3.7): address() reads the key of the client it is
 * encrypted to, which a grant does before it spends what the request presented, and issue() strikes it for
 * what was read and reads nothing of the client.
 */
interface IdTokenIssuerInterface
{
    /**
     * The shape the client registered for its ID tokens, with the key of the client they are encrypted to
     * when it registered an encryption, read now.
     *
     * @throws ClientKeysUnavailableException when the set the client publishes cannot be read, or holds no key its ID tokens can be encrypted to
     */
    public function address(Client $client): AddressedFormat;

    /**
     * @param AddressedFormat $addressed what address() read for the client of the authorization
     *
     * @return string the compact JWS, or the compact JWE that carries it
     */
    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedFormat $addressed, DateTimeImmutable $now): string;
}
