<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use Beffroi\Oidc\Exception\InvalidClientMetadataException;

/**
 * RFC 7591 §2
 */
final readonly class RegisteredMembers implements SelfAssertedMembersInterface
{
    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException
     */
    public function __construct(
        private array $members,
    ) {
        MembersOfTheDeployment::refuseIn($this);
    }

    public function source(): string
    {
        return 'the registration the client sent';
    }

    public function members(): array
    {
        return $this->members;
    }
}
