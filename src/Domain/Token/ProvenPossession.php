<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function array_any;

final readonly class ProvenPossession
{
    /**
     * @param list<ConfirmationInterface> $proofs in no particular order
     */
    private function __construct(
        public array $proofs,
    ) {
    }

    /**
     * @param list<ConfirmationInterface|null> $proofs one per way of proving, null where it proved none
     */
    public static function of(array $proofs): self
    {
        $proven = [];
        foreach ($proofs as $proof) {
            if ($proof !== null) {
                $proven[] = $proof;
            }
        }

        return new self($proven);
    }

    public static function none(): self
    {
        return new self([]);
    }

    public function proves(ConfirmationInterface $confirmation): bool
    {
        return array_any($this->proofs, static fn (ConfirmationInterface $proof): bool => $proof->matches($confirmation));
    }
}
