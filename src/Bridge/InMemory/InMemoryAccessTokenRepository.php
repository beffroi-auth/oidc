<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_values;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\OpaqueTokenValue;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokenInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryAccessTokenRepository implements AccessTokenRepositoryInterface, CanRevokeAccessTokenInterface, CanRevokeAccessTokensByGrantInterface, CanRevokeAccessTokensBySessionInterface
{
    /**
     * @var array<string, StoredAccessToken> by token hash
     */
    private array $tokens = [];

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): string
    {
        $value = OpaqueTokenValue::draw();
        $hash = OpaqueTokenValue::hash($value);
        $this->tokens[$hash] = StoredAccessToken::fromAuthorization($hash, $authorization, $now, $expiresAt);

        return $value;
    }

    /**
     * A record put there by a test, under the hash of the value it chose.
     */
    public function keep(StoredAccessToken $token): void
    {
        $this->tokens[$token->tokenHash] = $token;
    }

    public function find(string $token): ?StoredAccessToken
    {
        return $this->tokens[OpaqueTokenValue::hash($token)] ?? null;
    }

    public function revoke(StoredAccessToken $token): void
    {
        unset($this->tokens[$token->tokenHash]);
    }

    public function revokeByGrant(Uuid $grantId): array
    {
        return $this->remove(static fn (StoredAccessToken $token): bool => $token->grantId->equals($grantId));
    }

    public function revokeBySession(Uuid $session): array
    {
        return $this->remove(static fn (StoredAccessToken $token): bool => $token->session->id->equals($session));
    }

    /**
     * @return list<StoredAccessToken>
     */
    public function all(): array
    {
        return array_values($this->tokens);
    }

    /**
     * @param callable(StoredAccessToken): bool $matches
     *
     * @return list<StoredAccessToken>
     */
    private function remove(callable $matches): array
    {
        $removed = array_values(array_filter($this->tokens, $matches));
        foreach ($removed as $token) {
            unset($this->tokens[$token->tokenHash]);
        }

        return $removed;
    }
}
