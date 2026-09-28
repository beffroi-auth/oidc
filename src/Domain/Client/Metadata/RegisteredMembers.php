<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Metadata;

/**
 * The members a client registered itself (RFC 7591 §2): the body of the registration request, and the same
 * body read back from the row that kept it. One source for the two, because they are the same members: a
 * row is not a second spelling of a registration, and a member this provider learns to read tomorrow is
 * read from the rows that already carry it.
 *
 * RFC 7591 §3.1.1 puts it last of the sources a registration is read from: what a statement its issuer
 * signed says of the same member takes precedence over what the client sent in the clear.
 */
final readonly class RegisteredMembers implements ClientMetadataSourceInterface
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
        return 'the registration the client sent';
    }

    public function members(): array
    {
        return $this->members;
    }
}
