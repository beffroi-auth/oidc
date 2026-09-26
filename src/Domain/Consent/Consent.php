<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Consent;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a user agreed to let a client obtain about them (architecture §4.3). A new grant to the same client
 * supersedes the previous one, which is revoked.
 */
final class Consent implements ResolvesItsClientInterface
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
        $this->clientId = $client->registration->clientId;
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

    /**
     * Whether what a session obtained from this provider for a client was obtained under this consent:
     * the same user, the same client. The one place the rule is written for the stores that answer what
     * a consent taken back reaches, a grant, a refresh token, an access token (architecture §4.3).
     */
    public function covers(AuthenticationSession $session, string $clientId): bool
    {
        return $this->coversUser($session->user, $clientId);
    }

    /**
     * The same rule where no session is known yet: a record a client drew for a user it named, waiting for
     * that user to answer (RFC 8628 §3.2, CIBA Core §7), is a grant this consent covers before anybody has
     * signed in for it.
     */
    public function coversUser(User $user, string $clientId): bool
    {
        return $this->clientId === $clientId && $user->id->equals($this->user->id);
    }

    public function isFor(User $user, Client $client): bool
    {
        return $this->user->id->equals($user->id) && $this->client->equals($client);
    }

    public function clientHolder(): object
    {
        return $this;
    }
}
