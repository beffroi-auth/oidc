<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

final readonly class NestedMembers implements ClientMetadataSourceInterface
{
    /**
     * @param non-empty-string $source
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
