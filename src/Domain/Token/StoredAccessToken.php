<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An opaque access token as the provider keeps it (architecture §4.6): the SHA-256 of the value, and the
 * facts a self-contained token would carry as claims. Written once; a revoked token is removed and
 * becomes an unknown one (RFC 6750 §3.1).
 */
final readonly class StoredAccessToken
{
    public Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public string $clientId;

    /**
     * @param string $tokenHash see DrawnSecret::digestOf()
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant
     * @param ConfirmationInterface|null $confirmation what the token is bound to (RFC 8705 §3, RFC 9449 §6.1), null for a bearer token
     */
    public function __construct(
        public string $tokenHash,
        public Uuid $grantId,
        public Client $client,
        public AuthenticationSession $session,
        public Scopes $scopes,
        public ?ClaimsRequest $claimsRequest,
        public AuthenticationSnapshot $authentication,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?ConfirmationInterface $confirmation = null,
    ) {
        if (! DrawnSecret::isDigest($tokenHash)) {
            throw new InvalidArgumentException('An opaque access token is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An access token binds a session and a client of the same tenant.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An access token expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    public static function fromAuthorization(string $tokenHash, GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): self
    {
        return new self(
            $tokenHash,
            $authorization->grantId,
            $authorization->client,
            $authorization->session,
            $authorization->scopes,
            $authorization->claimsRequest,
            $authorization->authentication,
            $now,
            $expiresAt,
            $authorization->confirmation,
        );
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
