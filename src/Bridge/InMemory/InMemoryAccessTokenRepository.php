<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_values;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredUserAccessToken;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokenInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByConsentInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensByGrantInterface;
use Beffroi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Symfony\Component\Uid\Uuid;

final class InMemoryAccessTokenRepository implements
    AccessTokenRepositoryInterface,
    CanRevokeAccessTokenInterface,
    CanRevokeAccessTokensByConsentInterface,
    CanRevokeAccessTokensByGrantInterface,
    CanRevokeAccessTokensBySessionInterface
{
    /**
     * @var array<string, StoredAccessToken> by token hash
     */
    private array $tokens = [];

    public function save(StoredAccessToken $token): void
    {
        $this->tokens[$token->tokenHash] = $token;
    }

    public function find(string $token): ?StoredAccessToken
    {
        return $this->tokens[DrawnSecret::digestOf($token)] ?? null;
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
        return $this->remove(static fn (StoredAccessToken $token): bool => $token instanceof StoredUserAccessToken && $token->session->id->equals($session));
    }

    public function revokeByConsent(Consent $consent): array
    {
        return $this->remove(
            static fn (StoredAccessToken $token): bool => $token instanceof StoredUserAccessToken && $consent->covers($token->session, $token->clientId),
        );
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
