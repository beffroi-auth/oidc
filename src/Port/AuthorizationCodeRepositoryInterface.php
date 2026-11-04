<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * A used code stays, so that its replay can be told from an unknown code.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * @param string $codeHash see DrawnSecret::digestOf()
     */
    public function findByCodeHash(string $codeHash): ?AuthorizationCode;

    /**
     * Atomic: of concurrent requests presenting the same code, exactly one is told true, and a caller told false holds
     * a record whose state is the winner's (RFC 6749 §4.1.2, RFC 9700 §4.5).
     */
    public function consume(AuthorizationCode $code, DateTimeImmutable $now): bool;

    public function save(AuthorizationCode $code): void;
}
