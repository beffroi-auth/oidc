<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_keys;
use function array_values;
use function count;
use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Domain\Token\ConfirmationKindInterface;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use Heidi\Oidc\Port\ConfirmationReaderInterface;
use Heidi\Oidc\Port\ServedTokenSchemesInterface;
use function sprintf;

/**
 * The bindings the wiring gave the provider, the one source of truth over them (issue #98): reading a
 * "cnf" back asks them which member it names, and the schemes a resource reads a token under are theirs
 * plus the one of a token bound to nothing.
 *
 * A token is bound to one thing: it was issued on a request that proved one possession, and a "cnf"
 * naming two is not a "cnf" this provider wrote.
 */
final readonly class Confirmations implements ConfirmationReaderInterface, ServedTokenSchemesInterface
{
    /**
     * @var non-empty-list<ConfirmationKindInterface>
     */
    private array $kinds;

    /**
     * @param iterable<ConfirmationKindInterface> $kinds at least one, each answering for its own member
     *
     * @throws InvalidArgumentException when two kinds answer for one member, or when none is wired
     */
    public function __construct(iterable $kinds)
    {
        $wired = [];
        foreach ($kinds as $kind) {
            $member = $kind->member();
            if (isset($wired[$member])) {
                throw new InvalidArgumentException(sprintf('Two confirmation kinds answer for the "%s" member of a "cnf".', $member));
            }
            $wired[$member] = $kind;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('A provider binds its tokens with at least one kind of confirmation.');
        }
        $this->kinds = array_values($wired);
    }

    public function fromClaims(array $claims): ?ConfirmationInterface
    {
        $confirmation = $claims[ConfirmationInterface::CLAIM] ?? null;
        if ($confirmation === null) {
            return null;
        }

        return $this->fromMembers(is_array($confirmation) ? $confirmation : []);
    }

    public function fromMembers(array $members): ConfirmationInterface
    {
        $read = [];
        foreach ($this->kinds as $kind) {
            $value = $members[$kind->member()] ?? null;
            if ($value !== null) {
                $read[$kind->member()] = is_string($value)
                    ? $kind->of($value)
                    : throw new InvalidArgumentException(sprintf('The "%s" member of a "cnf" carries a thumbprint (RFC 7800 section 3.1).', $kind->member()));
            }
        }
        if (count($read) > 1) {
            throw new InvalidArgumentException(sprintf('A token of this provider is bound to one thing, not to %s (RFC 7800 section 3.1).', implode(
                ' and ',
                array_keys($read),
            )));
        }

        return (
            array_values($read)[0] ?? throw new InvalidArgumentException(sprintf('The "cnf" of a token of this provider names one of %s (RFC 7800 section 3.1).', implode(
                ', ',
                $this->members(),
            )))
        );
    }

    public function servedTokenSchemes(): array
    {
        $schemes = [TokenResponse::BEARER];
        foreach ($this->kinds as $kind) {
            if (! in_array($kind->scheme(), $schemes, true)) {
                $schemes[] = $kind->scheme();
            }
        }

        return $schemes;
    }

    /**
     * @return non-empty-list<non-empty-string>
     */
    private function members(): array
    {
        $members = [];
        foreach ($this->kinds as $kind) {
            $members[] = $kind->member();
        }

        return $members;
    }
}
