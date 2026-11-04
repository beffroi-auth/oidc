<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Consent;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

final class Consent implements ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public readonly Tenant $tenant;

    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly Client $client,
        public readonly Scopes $scopes,
        public readonly DateTimeImmutable $grantedAt,
        public readonly ?AuthorizationDetails $authorizationDetails = null,
        public readonly ClaimNames $claims = new ClaimNames(),
    ) {
        if (! $client->belongsTo($user->tenant)) {
            throw new InvalidArgumentException('A consent binds a user and a client of the same tenant.');
        }
        $this->tenant = $user->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * Revokes this consent and returns the one that supersedes it, holding what both were given.
     */
    public function extendedWith(Scopes $scopes, ?AuthorizationDetails $authorizationDetails, ClaimNames $claims, Uuid $id, DateTimeImmutable $now): self
    {
        $this->revoke($now);

        return new self(
            $id,
            $this->user,
            $this->client,
            new Scopes([...$this->scopes->all, ...$scopes->all]),
            $now,
            self::merged($this->authorizationDetails, $authorizationDetails),
            $this->claims->with($claims),
        );
    }

    private static function merged(?AuthorizationDetails $held, ?AuthorizationDetails $given): ?AuthorizationDetails
    {
        if ($held === null) {
            return $given;
        }

        return $given === null ? $held : $held->mergedWith($given);
    }

    public function isActive(): bool
    {
        return $this->revokedAt === null;
    }

    public function revoke(DateTimeImmutable $now): void
    {
        if ($this->revokedAt !== null) {
            return;
        }
        $this->revokedAt = $now;
    }

    public function covers(AuthenticationSession $session, string $clientId): bool
    {
        return $this->coversUser($session->user, $clientId);
    }

    public function coversUser(User $user, string $clientId): bool
    {
        return $this->clientId === $clientId && $user->id->equals($this->user->id);
    }

    /**
     * RFC 9396 §7
     */
    public function coversAuthorizationDetails(?AuthorizationDetails $details): bool
    {
        if ($details === null) {
            return true;
        }

        return $this->authorizationDetails !== null && $this->authorizationDetails->covers($details);
    }

    /**
     * OIDC Core §5.5
     *
     * The caller has already taken out the claims the scopes of this consent stand for.
     */
    public function coversClaims(ClaimNames $claims): bool
    {
        return $this->claims->covers($claims);
    }

    public function isFor(User $user, Client $client): bool
    {
        return $this->user->id->equals($user->id) && $this->client->equals($client);
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
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'claims' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'grantedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'revokedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'user' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
