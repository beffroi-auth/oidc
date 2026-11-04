<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_map;
use function array_values;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use function sprintf;

/**
 * The grants are read on first use, never at construction: a grant reads them and is wired among them.
 */
final readonly class ServedGrants implements ServedGrantsInterface
{
    /**
     * @param iterable<GrantInterface> $grants at least one
     */
    public function __construct(
        private iterable $grants,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function named(string $grantType): ?GrantInterface
    {
        return $this->wired()[$grantType] ?? null;
    }

    public function servedGrantTypes(): array
    {
        $types = array_map(
            static fn (GrantInterface $grant): GrantTypeName => $grant->grantType(),
            array_values($this->wired()),
        );
        /** @var non-empty-list<GrantTypeName> $types */
        return $types;
    }

    public function issuingRefreshTokens(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof IssuesRefreshTokensInterface);
    }

    public function spendingRefreshTokens(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof SpendsRefreshTokensInterface);
    }

    public function actingForTheClientItself(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof ActsForTheClientItselfInterface);
    }

    public function requiringClientAuthentication(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof RequiresClientAuthenticationInterface);
    }

    public function sendingTheUserToTheClient(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof SendsTheUserToTheClientInterface);
    }

    public function askingTheUserOnAnotherDevice(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof AsksTheUserOnAnotherDeviceInterface);
    }

    public function askingTheUserThroughABackchannel(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof AsksTheUserThroughABackchannelInterface);
    }

    public function exchangingTokens(): array
    {
        return $this->grantTypesOf(static fn (GrantInterface $grant): bool => $grant instanceof ExchangesATokenInterface);
    }

    /**
     * @param callable(GrantInterface): bool $declares
     *
     * @return list<GrantTypeName>
     */
    private function grantTypesOf(callable $declares): array
    {
        $types = [];
        foreach ($this->wired() as $grant) {
            if ($declares($grant)) {
                $types[] = $grant->grantType();
            }
        }

        return $types;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<string, GrantInterface> by grant type
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->grants as $grant) {
            $name = $grant->grantType()->value;
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('The grant "%s" is wired twice.', $name));
            }
            $wired[$name] = $grant;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('The token endpoint serves at least one grant.');
        }

        return $wired;
    }
}
