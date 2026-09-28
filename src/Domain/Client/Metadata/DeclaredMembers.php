<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Metadata;

/**
 * The members a deployment declared for a client in its own configuration (architecture §5.1). It is the
 * only source nobody sent over the wire, which is why it is the only one whose refusal stops a boot: a
 * deployment that mistyped a member is told at the moment it starts the provider and not at the first
 * request that would have been served wrongly.
 */
final readonly class DeclaredMembers implements ClientMetadataSourceInterface
{
    /**
     * @param array<string, mixed> $members
     */
    public function __construct(
        private array $members,
    ) {
    }

    public function source(): string
    {
        return 'the configuration of the deployment';
    }

    public function members(): array
    {
        return $this->members;
    }
}
