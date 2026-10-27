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
 * Mints the access token of a response (architecture §4.6): how it is written and how long it lives.
 *
 * What a caller of the token endpoint sees is one issuer, which writes the token in the shape the client
 * is registered for; the issuer of one shape declares which one it writes
 * (AccessTokenShapeIssuerInterface), and ServedAccessTokenShapes is the one that picks among them.
 *
 * A token is addressed before it is struck, and struck with what was read then, asking nothing of the KMS.
 * address() opens the key of the tenant the token is signed with and the kind of "sub" its client registered, for
 * a shape that signs it and names in it whoever signed in, which a grant somebody signed in for does before it
 * spends what the request presented, its authorization not built yet. addressFor() opens the key and reads what
 * the authorization makes the token carry from outside the provider, which a grant whose authorization exists
 * before it spends anything does then (the assertion grant, issue #876).
 */
interface AccessTokenIssuerInterface
{
    /**
     * What a token of that client needs from outside the provider, read now: the key of the tenant it is signed
     * with, opened by the KMS, and the kind of "sub" the client registered, opened, which for a pairwise client
     * unseals the salt of its tenant (OIDC Core §8.1), for a shape that signs the token and names the person in
     * it; nothing for a shape that does neither.
     *
     * @throws KeyNotFoundException when the tenant has no active key for the algorithm the token is signed with
     * @throws KmsUnavailableException when the KMS does not answer to open that key, which is not open yet, or the salt of a pairwise client
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind the client registered
     */
    public function address(Client $client): AddressedAccessToken;

    /**
     * What the token of that authorization needs from outside the provider, read now: the key of the tenant it is
     * signed with, for a shape that signs it; the kind of "sub" the client registered, opened as address() opens it,
     * when somebody signed in for the authorization, any other token naming the client or the subject the client
     * named; and, when its subject was named by what the client presented, the person it is about, sealed under the
     * KMS of the tenant, for a shape that carries it sealed (issue #641).
     *
     * @throws KeyNotFoundException when the tenant has no active key for the algorithm the token is signed with
     * @throws KmsUnavailableException when the KMS does not answer to open that key, which is not open yet, or the salt of a pairwise client, or to seal that person
     * @throws InvalidArgumentException when somebody signed in for the authorization and the wiring assigns no identifier of the kind the client registered
     */
    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken;

    /**
     * @param AddressedAccessToken $addressed what address() read for the client of the authorization, or addressFor() for the authorization itself
     *
     * @throws LogicException when the token carries something from outside the provider that was not read when it was addressed
     */
    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken;
}
