<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function end;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;

final class InMemoryInteractionRepository implements InteractionRepositoryInterface
{
    /**
     * @var array<string, Interaction>
     */
    private array $interactions = [];

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

    public function last(): ?Interaction
    {
        $last = end($this->interactions);

        return $last === false ? null : $last;
    }
}
