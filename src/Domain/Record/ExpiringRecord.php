<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Record;

use DateTimeImmutable;

/**
 * What the provider keeps for whoever holds the value that names it, for as long as that value is worth
 * anything: an authorization code, a refresh token, the reference a pushed request answers with. When the
 * lifetime runs out is the same question for all of them, asked of the instant the caller holds and never
 * of a clock of its own, so it is written here and not in each record.
 *
 * How long a record lives is the wiring's, and what an expired one refuses to do is read where it is
 * decided: a grant, an endpoint, a verifier.
 */
abstract class ExpiringRecord
{
    abstract public DateTimeImmutable $expiresAt { get; }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
