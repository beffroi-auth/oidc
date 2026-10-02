<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Oidc\Port\PairwiseSaltInterface;

/**
 * For tests and for the examples: a salt drawn once per tenant and written nowhere, so nothing here
 * survives the process and no two runs compute the same identifiers.
 */
final class InMemoryPairwiseSalt implements PairwiseSaltInterface
{
    /**
     * @var array<string, non-empty-string>
     */
    private array $salts = [];

    /**
     * @param positive-int $length how many bytes a salt is made of, the number a deployment draws
     */
    public function __construct(
        private readonly RandomnessInterface $randomness,
        private readonly int $length = 32,
    ) {
    }

    public function saltOf(Tenant $tenant): string
    {
        return $this->salts[$tenant->id->toRfc4122()] ??= $this->randomness->bytes($this->length);
    }
}
