<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Exchange;

use function array_map;
use function array_values;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use function sprintf;

/**
 * The types of token the wiring gave the exchange, in the order they are wired (RFC 8693 §3). The one source
 * of truth over them: the grant reads this list to know what a request may present, and a registration reads
 * it to know what a client may name. A type wired twice, and an exchange wired with none, are refused here,
 * where the wiring is collected.
 */
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
     * The type that reads what a request presented under this identifier, null for one the provider does not
     * read, whatever the shape of that identifier: what a request wrote is looked up, never read as a name.
     *
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
     * @return non-empty-array<string, PresentedTokenTypeInterface> by the identifier each type gives itself
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
