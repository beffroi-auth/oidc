<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function end;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Port\InteractionRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryInteractionRepository implements InteractionRepositoryInterface
{
    /**
     * @var array<string, Interaction>
     */
    private array $interactions = [];

    /**
     * How many times save() was called, for tests that must see a write happen on an object they already hold.
     */
    public private(set) int $saves = 0;

    public function find(string $id): ?Interaction
    {
        return $this->interactions[$id] ?? null;
    }

    public function save(Interaction $interaction): void
    {
        ++$this->saves;
        $this->interactions[$interaction->id] = $interaction;
    }

    /**
     * The interaction saved last, for tests that only hold the exception it ended with.
     */
    public function last(): ?Interaction
    {
        $last = end($this->interactions);

        return $last === false ? null : $last;
    }
}
