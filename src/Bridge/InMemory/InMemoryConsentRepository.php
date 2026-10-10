<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_values;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\CanPageActiveConsentsInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use function usort;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryConsentRepository implements ConsentRepositoryInterface, ActiveConsentsInterface, CanPageActiveConsentsInterface
{
    /**
     * @var array<string, Consent>
     */
    private array $consents = [];

    /**
     * For tests that must see a write happen on an object they already hold.
     */
    public private(set) int $saves = 0;

    /**
     * The active consent granted last; on a tie, the one saved last.
     */
    public function findActive(User $user, Client $client): ?Consent
    {
        $found = null;
        foreach ($this->consents as $consent) {
            if ($consent->isActive() && $consent->isFor($user, $client) && ($found === null || $consent->grantedAt >= $found->grantedAt)) {
                $found = $consent;
            }
        }

        return $found;
    }

    /**
     * @return Listing<Consent>
     */
    public function pageOfActiveConsents(User $user, Pagination $pagination): Listing
    {
        return Listing::of($this->activeOf($user), $pagination);
    }

    /**
     * @return list<Consent>
     */
    public function activeOf(User $user): array
    {
        $found = [];
        foreach ($this->consents as $consent) {
            if ($consent->isActive() && $consent->user->id->equals($user->id)) {
                $found[] = $consent;
            }
        }
        usort($found, static fn (Consent $a, Consent $b): int => [$b->grantedAt, $b->clientId] <=> [$a->grantedAt, $a->clientId]);

        return $found;
    }

    public function save(Consent $consent): void
    {
        ++$this->saves;
        $this->consents[$consent->id->toRfc4122()] = $consent;
    }

    /**
     * @return list<Consent>
     */
    public function all(): array
    {
        return array_values($this->consents);
    }
}
