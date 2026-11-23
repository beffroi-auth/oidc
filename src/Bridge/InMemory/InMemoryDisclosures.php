<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use Symfony\Component\Uid\Uuid;
use function usort;

final class InMemoryDisclosures implements DisclosuresInterface, DisclosuresOfAPersonInterface
{
    /**
     * @var array<string, Disclosure>
     */
    private array $disclosures = [];

    public function record(Disclosure $disclosure): void
    {
        $this->disclosures[$disclosure->id->toRfc4122()] = $disclosure;
    }

    public function everyDisclosureTo(User $user, int $howMany, ?Uuid $after = null): array
    {
        if ($howMany < 1) {
            return [];
        }
        $found = [];
        foreach ($this->disclosures as $disclosure) {
            if (! $disclosure->tenant->equals($user->tenant) || ! $disclosure->subject->equals($user->subject)) {
                continue;
            }
            if ($after === null || $disclosure->id->compare($after) > 0) {
                $found[] = $disclosure;
            }
        }
        usort($found, static fn (Disclosure $a, Disclosure $b): int => $a->id->compare($b->id));

        return array_slice($found, 0, $howMany);
    }

    /**
     * @return list<Disclosure>
     */
    public function all(): array
    {
        return array_values($this->disclosures);
    }
}
