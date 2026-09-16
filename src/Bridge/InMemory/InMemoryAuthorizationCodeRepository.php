<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_find;
use function array_values;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepositoryInterface
{
    /**
     * @var array<string, AuthorizationCode> by code hash
     */
    private array $codes = [];

    /**
     * How many times save() was called, for tests that must see a write happen on an object they already hold.
     */
    public private(set) int $saves = 0;

    public function findByCodeHash(string $codeHash): ?AuthorizationCode
    {
        return $this->codes[$codeHash] ?? null;
    }

    public function findByGrantId(Uuid $grantId): ?AuthorizationCode
    {
        return array_find($this->codes, static fn (AuthorizationCode $code): bool => $code->grantId->equals($grantId));
    }

    public function save(AuthorizationCode $code): void
    {
        ++$this->saves;
        $this->codes[$code->codeHash] = $code;
    }

    /**
     * @return list<AuthorizationCode>
     */
    public function all(): array
    {
        return array_values($this->codes);
    }
}
