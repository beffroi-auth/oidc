<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_find;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process, and one process has one request at
 * a time, which is what makes spending a token atomic here.
 */
final class InMemoryInitialAccessTokenRepository implements InitialAccessTokenRepositoryInterface
{
    /**
     * @var list<InitialAccessToken>
     */
    private array $tokens = [];

    public function findByDigest(Tenant $tenant, string $digest): ?InitialAccessToken
    {
        return array_find(
            $this->tokens,
            static fn (InitialAccessToken $token): bool => $token->belongsTo($tenant) && $token->matches($digest),
        );
    }

    public function spend(InitialAccessToken $token, DateTimeImmutable $now): bool
    {
        if (! $token->authorisesARegistration($now)) {
            return false;
        }
        $token->spend();

        return true;
    }

    public function save(InitialAccessToken $token): void
    {
        $this->tokens[] = $token;
    }
}
