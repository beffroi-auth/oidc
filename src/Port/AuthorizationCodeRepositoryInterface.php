<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * Where authorization codes wait for the token endpoint (architecture §4.4, §4.5). A used code stays, so
 * that its replay can be told from an unknown code; the record is also the grant, kept as long as a
 * token descending from it may be presented; whether that grant is still alive is asked of
 * RecordedGrantsInterface, which every record carrying a grant answers.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * @param string $codeHash see DrawnSecret::digestOf()
     */
    public function findByCodeHash(string $codeHash): ?AuthorizationCode;

    /**
     * Atomic: of any number of requests presenting the same code at once, exactly one is told true
     * (RFC 6749 §4.1.2, RFC 9700 §4.5). A caller told false holds a record whose state is the winner's.
     */
    public function consume(AuthorizationCode $code, DateTimeImmutable $now): bool;

    public function save(AuthorizationCode $code): void;
}
