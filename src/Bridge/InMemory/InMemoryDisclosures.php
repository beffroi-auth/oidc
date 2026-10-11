<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_slice;
use function array_values;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;
use function usort;

/**
 * For tests and for the examples: nothing here survives the process.
 *
 * It bounds no run of the retention, having no table to hold: what the contract of the port means by
 * bounded is a store that would otherwise delete a year of rows in one statement.
 */
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

    public function forgetBefore(Tenant $tenant, DateTimeImmutable $moment): int
    {
        $forgotten = 0;
        foreach ($this->disclosures as $key => $disclosure) {
            if ($disclosure->tenant->equals($tenant) && $disclosure->handedOverAt < $moment) {
                unset($this->disclosures[$key]);
                ++$forgotten;
            }
        }

        return $forgotten;
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
     * Everything it holds, which a test reads to say what was written down.
     *
     * @return list<Disclosure>
     */
    public function all(): array
    {
        return array_values($this->disclosures);
    }
}
