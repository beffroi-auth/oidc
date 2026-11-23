<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Record\ExpiringRecord;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use function min;

/**
 * RFC 6749 §6, RFC 9700 §4.14.2
 */
final class RefreshToken extends ExpiringRecord implements HashedTokenInterface, ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public readonly Tenant $tenant;

    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $rotatedAt = null;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param ResourceIndicators|null $resources the whole grant's, which a refresh may narrow (RFC 8707 §2.2)
     * @param AuthorizationDetails|null $authorizationDetails the whole grant's, which a refresh may narrow (RFC 9396 §7)
     * @param AuthenticationSnapshot $authentication as proven at the grant, the same for the whole family
     * @param DateTimeImmutable $expiresAt sliding, never past the family's
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
        if (! $family->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('A refresh token binds a family and a client of the same tenant.');
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
            $authorization->grantedResources,
            $authorization->grantedAuthorizationDetails,
            $authorization->claimsRequest,
            $authorization->authentication,
            $now,
            min($expiresAt, $family->expiresAt),
            // A confidential client authenticates at every refresh, so only a public client's token keeps its binding.
            $authorization->client->registration->isPublic() ? $authorization->confirmation : null,
        );
    }

    /**
     * RFC 9700 §4.14.2
     *
     * Where client authentication or a binding protects the token, rotation adds nothing and FAPI 2.0 Security
     * Profile §5.3.2.1-9 forbids it.
     */
    public function rotatesOnUse(): bool
    {
        return $this->client->registration->isPublic() && $this->confirmation === null;
    }

    /**
     * RFC 9449 §5
     */
    public function isRefreshedBy(?ConfirmationInterface $confirmation): bool
    {
        return $this->confirmation === null || $confirmation !== null && $confirmation->matches($this->confirmation);
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.14.2
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

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'claimsRequest' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'rotatedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'confirmation' => new NoPersonalDatum(Reason::WHAT_A_TOKEN_IS_BOUND_TO),
            'revokedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'tokenHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'family' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
