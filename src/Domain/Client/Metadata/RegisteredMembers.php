<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_key_exists;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use function sprintf;

/**
 * The members a client registered itself (RFC 7591 §2): the body of the registration request, and the same
 * body read back from the row that kept it. One source for the two, because they are the same members: a
 * row is not a second spelling of a registration, and a member this provider learns to read tomorrow is
 * read from the rows that already carry it.
 *
 * RFC 7591 §3.1.1 puts it last of the sources a registration is read from: what a statement its issuer
 * signed says of the same member takes precedence over what the client sent in the clear.
 *
 * What a client may register is what the specifications define. The members this provider defines for
 * itself are written by a deployment that declares a client, or by the registration policy of a tenant
 * (`AssignedMembers`), and a client that sends one is refused rather than obeyed: they are the named
 * exceptions of decision 0006 and the privileges a tenant grants, and a client that registers itself
 * gets nothing a declared client does not get by asking for it (decision 0009).
 */
final readonly class RegisteredMembers implements ClientMetadataSourceInterface
{
    /**
     * The members of this provider and of no specification. A member RFC 7591 §2 or OIDC Registration §2
     * defines is not one of them, however much it grants: those a client registers, and what it may
     * register them to is held to what its tenant offers.
     *
     * @var list<string>
     */
    public const array WRITTEN_BY_THE_DEPLOYMENT = [
        'requires_consent',
        'requires_pkce',
        'access_token_format',
        'resources',
        'token_exchange',
        'may_act',
        'require_sender_constrained_tokens',
    ];

    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException when a member of this provider alone was sent by a client
     */
    public function __construct(
        private array $members,
    ) {
        foreach (self::WRITTEN_BY_THE_DEPLOYMENT as $member) {
            if (array_key_exists($member, $members)) {
                throw new InvalidClientMetadataException(
                    $member,
                    $this->source(),
                    sprintf(
                        'The member "%s" is not one a client registers: it is written by whoever declares a client or by the registration policy of the tenant, and never asked for (decision 0009).',
                        $member,
                    ),
                );
            }
        }
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
