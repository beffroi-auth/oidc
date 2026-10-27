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
 * Mints the ID token of a response (OIDC Core §2, architecture §4.6); the access token is given for "at_hash".
 *
 * An ID token describes who signed in, so it is issued from an authorization somebody signed in for and
 * from no other: a grant with nobody behind it has none to carry (RFC 6749 §4.4.3).
 *
 * It is addressed before it is struck (OIDC Core §3.1.3.7): address() opens the key of the tenant it is signed
 * with and the kind of "sub" the client registered, and reads the key of the client it is encrypted to, which a
 * grant does before it spends what the request presented, and issue() strikes it for what was read and asks
 * nothing of the KMS or of the client.
 */
interface IdTokenIssuerInterface
{
    /**
     * The shape the client registered for its ID tokens, with the key of the tenant they are signed with,
     * opened, and the key of the client they are encrypted to when it registered an encryption, read now; and
     * the kind of "sub" the client registered, opened, which for a pairwise client unseals the salt of its
     * tenant (OIDC Core §8.1).
     *
     * @throws KeyNotFoundException when the tenant has no active key for the algorithm its ID tokens are signed with
     * @throws KmsUnavailableException when the KMS does not answer to open that key, which is not open yet, or the salt of a pairwise client
     * @throws ClientKeysUnavailableException when the set the client publishes cannot be read, or holds no key its ID tokens can be encrypted to
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function address(Client $client): AddressedIdToken;

    /**
     * @param AddressedIdToken $addressed what address() read for the client of the authorization
     *
     * @return string the compact JWS, or the compact JWE that carries it
     */
    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, AddressedIdToken $addressed, DateTimeImmutable $now): string;
}
