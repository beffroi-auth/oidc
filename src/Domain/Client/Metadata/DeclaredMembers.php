<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * The members a deployment declared for a client in its configuration.
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
