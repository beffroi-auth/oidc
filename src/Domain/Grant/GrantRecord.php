<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Grant;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Record\RecordReadOnce;
use Symfony\Component\Uid\Uuid;

/**
 * The record a token descends from (architecture §4.6): an authorization code, a device authorization
 * request, a backchannel authentication request. Each of them is handed out once, read once and names the
 * grant by an opaque identifier the tokens carry, and whether that grant is still alive is the second of
 * the three questions a resource of this provider asks of every token somebody signed in for.
 *
 * Being that record is the same fact whatever the flow drew it, and the same rules, so the identifier and
 * the revocation are written here once and not in each record, as the core writes what a revocable
 * credential is (RevocableCredential). A grant is revoked for the reasons the protocol and the provider
 * name: a code presented twice (RFC 6749 §4.1.2), a consent taken back (architecture §4.3); the date of
 * the first revocation is the one that stays, revoking a second time being nothing.
 *
 * A grant nothing kept a record of would be a token no resource of this provider can answer for, which is
 * why a flow that issues tokens without writing a code writes one of these instead.
 */
abstract class GrantRecord extends RecordReadOnce
{
    /**
     * What the access tokens of this grant carry as "grant_id", and what the store keeps under a unique
     * constraint: one record is one grant.
     */
    abstract public Uuid $grantId { get; }

    public private(set) ?DateTimeImmutable $revokedAt = null;

    public function revoke(DateTimeImmutable $now): void
    {
        $this->revokedAt ??= $now;
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }
}
