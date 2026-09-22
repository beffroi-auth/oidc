<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_any;

/**
 * What a request proved it holds, said in the very terms a token is bound in (RFC 7800 §3.1): the
 * certificate the connection carried, the key a DPoP proof was signed with, both, or nothing at all.
 *
 * A resource asks it one question, whether the token it was handed is honoured here, and never which
 * kind of proof answered: a binding of a kind added later is proven the same way, by a confirmation
 * equal to the one the token carries.
 */
final readonly class ProvenPossession
{
    /**
     * @param list<ConfirmationInterface> $proofs what the request proved, in no particular order
     */
    private function __construct(
        public array $proofs,
    ) {
    }

    /**
     * @param list<ConfirmationInterface|null> $proofs what each way of proving a possession made of the
     *                                                request, null where it proved none
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

    /**
     * A request that proved nothing, which is every request of a client that binds no token.
     */
    public static function none(): self
    {
        return new self([]);
    }

    public function proves(ConfirmationInterface $confirmation): bool
    {
        return array_any($this->proofs, static fn (ConfirmationInterface $proof): bool => $proof->matches($confirmation));
    }
}
