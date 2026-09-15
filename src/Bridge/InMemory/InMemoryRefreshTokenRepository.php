<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_values;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * @var array<string, RefreshToken> by token hash
     */
    private array $tokens = [];

    /**
     * How many times save() was called, for tests that must see a write happen on an object they already hold.
     */
    public private(set) int $saves = 0;

    public function findByTokenHash(string $tokenHash): ?RefreshToken
    {
        return $this->tokens[$tokenHash] ?? null;
    }

    public function findByFamily(Uuid $family): array
    {
        return array_values(array_filter($this->tokens, static fn (RefreshToken $token): bool => $token->family->id->equals($family)));
    }

    public function findByAuthorizationCode(string $codeHash): array
    {
        return array_values(array_filter($this->tokens, static fn (RefreshToken $token): bool => $token->family->authorizationCodeHash === $codeHash));
    }

    public function save(RefreshToken $token): void
    {
        ++$this->saves;
        $this->tokens[$token->tokenHash] = $token;
    }

    /**
     * @return list<RefreshToken>
     */
    public function all(): array
    {
        return array_values($this->tokens);
    }
}
