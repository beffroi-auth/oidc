<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_key_exists;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use function sprintf;

/**
 * The members of this provider and of no specification: written by a deployment that declares a client, or
 * by the registration policy of a tenant (`AssignedMembers`), and by nothing that describes a client that
 * registers itself, whether the client sent them in the clear (`RegisteredMembers`) or an authority signed
 * them (`AttestedMembers`). They are the named exceptions of decision 0006 and the privileges a tenant
 * grants, and a client that registers itself gets nothing a declared client does not get by asking for it,
 * nor by having it signed (decision 0009): what describes a client says what it is, never what it may have.
 *
 * One list for the two sources, because the two end in the same row: what a statement signed is kept among
 * what the client sent and read back from it as `RegisteredMembers`, so a member one of them let through
 * would be a client registered with it and then served as no client at all.
 *
 * A member RFC 7591 §2 or OIDC Registration §2 defines is not one of them, however much it grants: those a
 * client registers, and what it may register them to is held to what its tenant offers.
 */
final readonly class MembersOfTheDeployment
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        'requires_consent',
        'requires_pkce',
        'access_token_format',
        'resources',
        'token_exchange',
        'may_act',
        'require_sender_constrained_tokens',
    ];

    /**
     * A member carried as null is carried all the same: the source names it, and naming it is what is
     * refused.
     *
     * @throws InvalidClientMetadataException when the source carries one of them, named with that source
     */
    public static function refuseIn(ClientMetadataSourceInterface $source): void
    {
        $members = $source->members();
        foreach (self::NAMES as $member) {
            if (array_key_exists($member, $members)) {
                throw new InvalidClientMetadataException(
                    $member,
                    $source->source(),
                    sprintf(
                        'The member "%s" is not one a client registers: it is written by whoever declares a client or by the registration policy of the tenant, and never asked for (decision 0009).',
                        $member,
                    ),
                );
            }
        }
    }
}
