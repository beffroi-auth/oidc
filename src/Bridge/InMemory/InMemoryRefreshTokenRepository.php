<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_values;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;
use Beffroi\Oidc\Port\RefreshTokenRepositoryInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use Symfony\Component\Uid\Uuid;

final class InMemoryRefreshTokenRepository implements RefreshTokenRepositoryInterface, RefreshTokensOfAConsentInterface
{
    /**
     * @var array<string, RefreshToken> by token hash
     */
    private array $tokens = [];

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
        return array_values(array_filter($this->tokens, static fn (RefreshToken $token): bool => $token->family->grantingRecordHash === $codeHash));
    }

    public function findBySession(Uuid $session): array
    {
        return array_values(array_filter($this->tokens, static fn (RefreshToken $token): bool => $token->session->id->equals($session)));
    }

    public function ofConsent(Consent $consent): array
    {
        return array_values(array_filter($this->tokens, static fn (RefreshToken $token): bool => $consent->covers($token->session, $token->clientId)));
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
