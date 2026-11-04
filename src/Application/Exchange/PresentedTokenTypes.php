<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Exchange;

use function array_map;
use function array_values;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use function sprintf;

final readonly class PresentedTokenTypes implements PresentedTokenTypesInterface
{
    /**
     * @param iterable<PresentedTokenTypeInterface> $types at least one
     */
    public function __construct(
        private iterable $types,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function named(string $identifier): ?PresentedTokenTypeInterface
    {
        return $this->wired()[$identifier] ?? null;
    }

    public function presentedTokenTypes(): array
    {
        $identifiers = array_map(
            static fn (PresentedTokenTypeInterface $type): TokenTypeIdentifier => $type->identifier(),
            array_values($this->wired()),
        );
        /** @var non-empty-list<TokenTypeIdentifier> $identifiers */
        return $identifiers;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<string, PresentedTokenTypeInterface> by identifier
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->types as $type) {
            $identifier = $type->identifier()->value;
            if (isset($wired[$identifier])) {
                throw new InvalidArgumentException(sprintf('The token type "%s" is wired twice.', $identifier));
            }
            $wired[$identifier] = $type;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('The token exchange reads at least one type of token (RFC 8693 section 3).');
        }

        return $wired;
    }
}
