<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function end;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;

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
     * For tests that must see a write happen on an object they already hold.
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
     * For tests that only hold the exception it ended with.
     */
    public function last(): ?Interaction
    {
        $last = end($this->interactions);

        return $last === false ? null : $last;
    }
}
