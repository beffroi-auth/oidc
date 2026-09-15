<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_values;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepositoryInterface
{
    /**
     * @var array<string, AuthorizationCode> by code hash
     */
    private array $codes = [];

    public function save(AuthorizationCode $code): void
    {
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
