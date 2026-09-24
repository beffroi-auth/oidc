<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Consent;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scopes;
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

    public private(set) ?DateTimeImmutable $revokedAt = null;

    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly Client $client,
        public readonly Scopes $scopes,
        public readonly DateTimeImmutable $grantedAt,
    ) {
        if (! $client->belongsTo($user->tenant)) {
            throw new InvalidArgumentException('A consent binds a user and a client of the same tenant.');
        }
        $this->tenant = $user->tenant;
        $this->clientId = $client->clientId;
    }

    /**
     * The consent that supersedes this one when the user agrees to more: its scopes and the ones given,
     * each once, from now; this one is revoked. What a user agreed to is never taken back by a new
     * agreement (architecture §4.3).
     *
     */
    public function extendedWith(Scopes $scopes, Uuid $id, DateTimeImmutable $now): self
    {
        $this->revoke($now);

        return new self($id, $this->user, $this->client, new Scopes([...$this->scopes->all, ...$scopes->all]), $now);
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
