<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_key_exists;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use function sprintf;

/**
 * The members this provider defines: written by a deployment, a tenant's policy or its initial access token, refused from a
 * client.
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
     * A member carried as null is refused all the same: naming it is what is refused.
     *
     * @throws InvalidClientMetadataException
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
                        'The member "%s" is not one a client registers: it is written by whoever declares a client, by the registration policy of the tenant or by the initial access token the tenant issued, and never asked for (decisions 0009 and 0043).',
                        $member,
                    ),
                );
            }
        }
    }
}
