<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Metadata;

/**
 * The members a member of a registration carries itself: "token_exchange" is a map of its own (RFC 8693
 * §2.1), read by the same reader, refused the same way, and named by whatever carried the member it is
 * inside. It is a source because that is what the reader reads, and it is never one of the sources a
 * registration is read from.
 */
final readonly class NestedMembers implements ClientMetadataSourceInterface
{
    /**
     * @param non-empty-string $source where the member that carries these came from
     * @param array<string, mixed> $members
     */
    public function __construct(
        private string $source,
        private array $members,
    ) {
    }

    public function source(): string
    {
        return $this->source;
    }

    public function members(): array
    {
        return $this->members;
    }
}
