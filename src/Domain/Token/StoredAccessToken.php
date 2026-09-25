<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
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
abstract readonly class StoredAccessToken implements HashedTokenInterface, ResolvesItsClientInterface
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

    public function clientHolder(): object
    {
        return $this;
    }
}
