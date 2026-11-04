<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_key_exists;
use function array_keys;
use Beffroi\Oidc\Exception\LogicException;
use function in_array;
use function sprintf;

/**
 * RFC 7591 §2, §3.1.1
 *
 * A member a source carries as null is not carried: a configuration tree writes null for every option nobody set.
 */
final readonly class ClientMetadata
{
    /**
     * @param non-empty-list<ClientMetadataSourceInterface> $sources the first one wins
     */
    public function __construct(
        private array $sources,
    ) {
    }

    public function has(string $member): bool
    {
        return $this->carrying($member) !== null;
    }

    public function value(string $member): mixed
    {
        $source = $this->carrying($member);

        return $source === null ? null : $source->members()[$member];
    }

    /**
     * @throws LogicException
     *
     * @return non-empty-string
     */
    public function sourceOf(string $member): string
    {
        $source = $this->carrying($member);
        if ($source === null) {
            throw new LogicException(sprintf('No source of this registration carries a "%s".', $member));
        }

        return $source->source();
    }

    /**
     * @return list<string>
     */
    public function members(): array
    {
        $members = [];
        foreach ($this->sources as $source) {
            foreach (array_keys($source->members()) as $member) {
                if (! in_array($member, $members, true)) {
                    $members[] = $member;
                }
            }
        }

        return $members;
    }

    private function carrying(string $member): ?ClientMetadataSourceInterface
    {
        foreach ($this->sources as $source) {
            $members = $source->members();
            if (array_key_exists($member, $members) && $members[$member] !== null) {
                return $source;
            }
        }

        return null;
    }
}
