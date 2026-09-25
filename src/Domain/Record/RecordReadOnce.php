<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Record;

use DateTimeImmutable;
use Heidi\Oidc\Exception\LogicException;
use function sprintf;

/**
 * A record the provider hands out once and reads once: an authorization code (RFC 6749 §4.1.2), the
 * reference a pushed request answers with (RFC 9126 §4). Being read once is the same fact whatever the
 * record, and the same rules, so they are written here once, as the core writes what a revocable
 * credential is (RevocableCredential): the repository claims the record atomically and consumes it on the
 * winner, a claim that was lost records the instant the store holds, and the record stays after its use so
 * that a second presentation is told from a reference nobody ever issued.
 *
 * Consuming one twice is a programming error and not a replay: whoever consumes reads isUsed() first, and
 * the refusal names the record and that reader, which is what it is for.
 */
abstract class RecordReadOnce extends ExpiringRecord
{
    public private(set) ?DateTimeImmutable $usedAt = null;

    /**
     * @throws LogicException when the record was consumed already
     */
    public function consume(DateTimeImmutable $now): void
    {
        if ($this->usedAt !== null) {
            throw new LogicException(sprintf('%s is consumed once; %s checks isUsed() first.', $this->nameOfRecord(), $this->readerThatChecks()));
        }
        $this->usedAt = $now;
    }

    /**
     * For a repository whose claim was lost: the instant the store holds.
     */
    public function recordConsumption(DateTimeImmutable $usedAt): void
    {
        $this->usedAt = $usedAt;
    }

    public function isUsed(): bool
    {
        return $this->usedAt !== null;
    }

    /**
     * How the record names itself where it refuses a second consumption, the article included: "An
     * authorization code", "A pushed authorization request".
     */
    abstract protected function nameOfRecord(): string;

    /**
     * Who reads isUsed() before consuming, and is therefore the one that got it wrong: "the grant", "the
     * authorization endpoint".
     */
    abstract protected function readerThatChecks(): string;
}
