<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_values;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Port\ConsentRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryConsentRepository implements ConsentRepositoryInterface
{
    /**
     * @var array<string, Consent>
     */
    private array $consents = [];

    /**
     * How many times save() was called, for tests that must see a write happen on an object they already hold.
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
