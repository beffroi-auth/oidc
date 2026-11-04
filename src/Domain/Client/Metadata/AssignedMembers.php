<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * The members a tenant's registration policy wrote on a registration, which no client sends.
 */
final readonly class AssignedMembers implements ClientMetadataSourceInterface
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
        return 'the registration policy of the tenant';
    }

    public function members(): array
    {
        return $this->members;
    }
}
