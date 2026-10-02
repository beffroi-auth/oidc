<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_find;
use function array_reverse;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use Symfony\Component\Uid\Uuid;

/**
 * For tests and for the examples: nothing here survives the process, and one process has one request at
 * a time, which is what makes spending a token atomic here.
 */
final class InMemoryInitialAccessTokenRepository implements InitialAccessTokenRepositoryInterface, IssuedInitialAccessTokensInterface
{
    /**
     * @var array<string, InitialAccessToken> by identifier, in the order they were issued
     */
    private array $tokens = [];

    public function findByDigest(Tenant $tenant, string $digest): ?InitialAccessToken
    {
        return array_find(
            $this->tokens,
            static fn (InitialAccessToken $token): bool => $token->belongsTo($tenant) && $token->matches($digest),
        );
    }

    public function find(Tenant $tenant, Uuid $id): ?InitialAccessToken
    {
        $token = $this->tokens[$id->toRfc4122()] ?? null;

        return $token?->belongsTo($tenant) === true ? $token : null;
    }

    public function issuedIn(Tenant $tenant): iterable
    {
        foreach (array_reverse($this->tokens) as $token) {
            if ($token->belongsTo($tenant)) {
                yield $token;
            }
        }
    }

    public function spend(InitialAccessToken $token, DateTimeImmutable $now): bool
    {
        if (! $token->authorisesARegistration($now)) {
            return false;
        }
        $token->spend();

        return true;
    }

    /**
     * A token saved twice is one token: what is kept is by identifier, so writing back one that was
     * revoked replaces the row rather than adding a second of the same name.
     */
    public function save(InitialAccessToken $token): void
    {
        $this->tokens[$token->id->toRfc4122()] = $token;
    }
}
