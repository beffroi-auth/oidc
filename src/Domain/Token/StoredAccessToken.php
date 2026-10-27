<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token as the provider keeps it (architecture §4.6): the SHA-256 of the value, and the
 * facts a self-contained token would carry as claims. Written once; a revoked token is removed and
 * becomes an unknown one (RFC 6750 §3.1).
 *
 * What every kind of token keeps is here. A token somebody signed in for keeps the session it descends
 * from and what that session had proven (StoredUserAccessToken), a token a client holds for itself keeps
 * neither (StoredClientAccessToken); each kind has a table of its own, so that a row never carries a
 * column its kind has nothing to write in.
 */
abstract readonly class StoredAccessToken implements HashedTokenInterface, ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public string $clientId;

    /**
     * @param string $tokenHash see DrawnSecret::digestOf()
     * @param ResourceIndicators|null $resources the resources this token is addressed to (RFC 8707 §2), null when the request named none and the token is addressed to its client
     * @param ConfirmationInterface|null $confirmation what the token is bound to (RFC 8705 §3, RFC 9449 §6.1), null for a bearer token
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $tokenHash,
        public Uuid $grantId,
        public Client $client,
        public Scopes $scopes,
        public ?ResourceIndicators $resources,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
    ) {
        if (! DrawnSecret::isDigest($tokenHash)) {
            throw new InvalidArgumentException('An opaque access token is stored as its hex SHA-256.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * Who this token is addressed to (RFC 8707 §2), by the rule the self-contained shape writes into
     * its "aud": what the introspection of this token renders, and what a resource server reads there.
     */
    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * The person the token was issued in the name of, by the subject their account carries, which is the
     * name the journal of a person is read under (issue #588); null when the record names nobody that
     * journal can find. Each kind answers for itself, there being nothing to recognise a kind by.
     */
    abstract public function person(): ?Subject;

    /**
     * The session that names the person the token was issued in the name of, by its identifier, null when the record
     * keeps that person itself or names nobody, which person() then answers. The identifier is what a store hands over
     * of a session it has not opened yet, so whoever must not open that session reads the person where the store of
     * sessions keeps their subject in the clear (decision 0011, issue #888).
     */
    abstract public function sessionNamingItsPerson(): ?Uuid;

    public function clientHolder(): object
    {
        return $this;
    }

    /**
     * What every access token of this provider holds, whoever it was issued for: the lines the tables of the
     * three kinds share are declared here once, as their mapping is.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'confirmation' => new NoPersonalDatum(Reason::WHAT_A_TOKEN_IS_BOUND_TO),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'tokenHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
