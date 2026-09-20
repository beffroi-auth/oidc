<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Consent;

use function array_all;
use function array_any;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a user agreed to let a client obtain about them (architecture §4.3). A new grant to the same client
 * supersedes the previous one, which is revoked.
 */
final class Consent
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * @var non-empty-list<Scope>
     */
    public readonly array $scopes;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param list<Scope> $scopes at least one
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly Client $client,
        array $scopes,
        public readonly DateTimeImmutable $grantedAt,
    ) {
        if (! $client->belongsTo($user->tenant)) {
            throw new InvalidArgumentException('A consent binds a user and a client of the same tenant.');
        }
        $unique = [];
        foreach ($scopes as $scope) {
            if (! array_any($unique, static fn (Scope $kept): bool => $kept->equals($scope))) {
                $unique[] = $scope;
            }
        }
        if ($unique === []) {
            throw new InvalidArgumentException('A consent covers at least one scope.');
        }
        $this->tenant = $user->tenant;
        $this->clientId = $client->clientId;
        $this->scopes = $unique;
    }

    /**
     * The consent that supersedes this one when the user agrees to more: its scopes and the ones given,
     * each once, from now; this one is revoked. What a user agreed to is never taken back by a new
     * agreement (architecture §4.3).
     *
     * @param list<Scope> $scopes
     */
    public function extendedWith(array $scopes, Uuid $id, DateTimeImmutable $now): self
    {
        $this->revoke($now);

        return new self($id, $this->user, $this->client, [...$this->scopes, ...$scopes], $now);
    }

    /**
     * @param list<Scope> $scopes
     */
    public function covers(array $scopes): bool
    {
        return array_all($scopes, fn (Scope $scope): bool => $this->hasScope($scope));
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }

    public function isActive(): bool
    {
        return $this->revokedAt === null;
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

    public function isFor(User $user, Client $client): bool
    {
        return $this->user->id->equals($user->id) && $this->client->equals($client);
    }
}
