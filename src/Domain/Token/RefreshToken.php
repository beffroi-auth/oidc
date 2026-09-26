<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Heidi\Oidc\Domain\Record\ExpiringRecord;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function min;

/**
 * A refresh token (RFC 6749 §6, architecture §4.6) as the provider keeps it: the SHA-256 of the value,
 * its family, the authentication of the original authorization carried along the rotations (OIDC Core
 * §12.2). Presented once; a second presentation is a reuse (RFC 9700 §4.13.2).
 *
 * One issued to a public client keeps what the request that got it proved (RFC 8705 §4, RFC 9449 §5):
 * such a client has no credentials, so the binding is the only thing that tells its holder from
 * whoever took a copy. One issued to a confidential client keeps none: what it authenticates with is
 * what it is asked for again, at every refresh.
 */
final class RefreshToken extends ExpiringRecord implements HashedTokenInterface, ResolvesItsClientInterface
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $rotatedAt = null;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param string $tokenHash the hex SHA-256 of the value drawn for it, see DrawnSecret
     * @param ResourceIndicators|null $resources the resources of the whole grant, which a refresh is bound to and may narrow (RFC 8707 §2.2), null when the authorization named none
     * @param AuthorizationDetails|null $authorizationDetails what the user agreed to beyond the scopes, which a refresh is bound to and may narrow (RFC 9396 §7), null when they agreed to none
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant, the same for the whole family
     * @param ConfirmationInterface|null $confirmation what a refresh of this token has to prove again (RFC 9449 §5), null when the client proves itself another way
     * @param DateTimeImmutable $expiresAt the sliding expiry, never past the one of the family
     */
    public function __construct(
        public readonly string $tokenHash,
        public readonly RefreshTokenFamily $family,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        public readonly Scopes $scopes,
        public readonly ?ResourceIndicators $resources,
        public readonly ?AuthorizationDetails $authorizationDetails,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly AuthenticationSnapshot $authentication,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?ConfirmationInterface $confirmation = null,
    ) {
        if (! DrawnSecret::isDigest($tokenHash)) {
            throw new InvalidArgumentException('A refresh token is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('A refresh token binds a session and a client of the same tenant.');
        }
        if ($issuedAt < $family->startedAt) {
            throw new InvalidArgumentException('A refresh token is issued after its family started.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A refresh token expires after it was issued.');
        }
        if ($expiresAt > $family->expiresAt) {
            throw new InvalidArgumentException('A refresh token never outlives its family.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    public static function fromAuthorization(
        string $tokenHash,
        RefreshTokenFamily $family,
        UserAuthorizationInterface $authorization,
        DateTimeImmutable $now,
        DateTimeImmutable $expiresAt,
    ): self {
        return new self(
            $tokenHash,
            $family,
            $authorization->client,
            $authorization->session,
            $authorization->grantedScopes,
            // RFC 8707 §2.2, RFC 9396 §7: a refresh token is bound to the full original grant, whatever
            // subset of its resources and of its details the access token beside it was narrowed to
            $authorization->grantedResources,
            $authorization->grantedAuthorizationDetails,
            $authorization->claimsRequest,
            $authorization->authentication,
            $now,
            min($expiresAt, $family->expiresAt),
            // RFC 8705 §4, RFC 9449 §5: a public client is bound by what it proved, a confidential one
            // by what it authenticates with, which the endpoint asks of it again anyway
            $authorization->client->registration->isPublic() ? $authorization->confirmation : null,
        );
    }

    /**
     * Whether this token is protected by being replaced at every use (RFC 9700 §4.13.2), which is the
     * last term of a disjunction and not a rule of its own. A refresh token is told from a copy of
     * itself by one of three things: the authentication of a confidential client, the key or the
     * certificate it is bound to, or rotation. Where one of the first two holds, rotation adds nothing,
     * and FAPI 2.0 Security Profile §5.3.2.1-9 forbids it for that very reason: a client that loses the
     * answer to a refresh would be locked out of a grant it still holds.
     */
    public function rotatesOnUse(): bool
    {
        return $this->client->registration->isPublic() && $this->confirmation === null;
    }

    /**
     * RFC 9449 §5: whether the request refreshing this token proved what it is bound to. A token bound
     * to nothing is refreshed by the client it was issued to, which the endpoint authenticated before
     * the grant was even reached.
     */
    public function isRefreshedBy(?ConfirmationInterface $confirmation): bool
    {
        return $this->confirmation === null || $confirmation !== null && $confirmation->matches($this->confirmation);
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13.2. The grant reads isRotated() first: a second presentation is a reuse.
     */
    public function rotate(DateTimeImmutable $now): void
    {
        if ($this->rotatedAt !== null) {
            throw new LogicException('A refresh token is rotated once; the grant checks isRotated() first.');
        }
        if ($this->revokedAt !== null) {
            throw new LogicException('A revoked refresh token is not rotated.');
        }
        $this->rotatedAt = $now;
    }

    /**
     * The first revocation wins.
     */
    public function revoke(DateTimeImmutable $now): void
    {
        if ($this->revokedAt !== null) {
            return;
        }
        $this->revokedAt = $now;
    }

    public function isRotated(): bool
    {
        return $this->rotatedAt !== null;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    public function clientHolder(): object
    {
        return $this;
    }
}
