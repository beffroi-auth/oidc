<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_key_exists;
use function array_keys;
use Beffroi\Oidc\Exception\LogicException;
use function in_array;
use function sprintf;

/**
 * The metadata a client is registered with, read from an ordered set of sources (RFC 7591 §2, §3.1.1): the
 * first source that carries a member is the one that answers for it, so a source is put in front of
 * another and never merged into it.
 *
 * A member a source carries as null is a member it does not carry: a configuration tree fills every option
 * nobody wrote with null, and a body that sends a member as JSON null sends nothing about it.
 *
 * It answers what a value is and where it came from, and nothing about what a value means: what a member
 * is read as is the reader's (ClientMetadataReader), and the names are read there and nowhere else.
 */
final readonly class ClientMetadata
{
    /**
     * @param non-empty-list<ClientMetadataSourceInterface> $sources the one that wins first
     */
    public function __construct(
        private array $sources,
    ) {
    }

    /**
     * Whether any source carries that member.
     */
    public function has(string $member): bool
    {
        return $this->carrying($member) !== null;
    }

    /**
     * The value of that member, from the first source that carries it, or null when no source does.
     */
    public function value(string $member): mixed
    {
        $source = $this->carrying($member);

        return $source === null ? null : $source->members()[$member];
    }

    /**
     * Where the value of that member came from, as a refusal names it.
     *
     * @throws LogicException when no source carries that member
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
     * Every member any source carries, each once, in the order the sources carry them: what the reader
     * checks its own names against, so that a member nobody reads is refused wherever it was written.
     *
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
