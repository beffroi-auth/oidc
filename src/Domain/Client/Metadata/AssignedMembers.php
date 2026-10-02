<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * The members the provider itself wrote on a registration it created, which no client ever sends: what
 * the registration policy of a tenant grants the clients it registers (decision 0017), read from the
 * policy at the moment that policy writes the registration and from nothing else afterwards.
 *
 * It is a source of its own because of what it is not: it is not what the client asked for, so it is not
 * read back from the body a row kept (`RegisteredMembers`), and it is not what a deployment declared, so
 * it is not the configuration either. A registration the policy writes again, the replacement of
 * RFC 7592 §2.2, takes what the policy writes then and not what it wrote before.
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
