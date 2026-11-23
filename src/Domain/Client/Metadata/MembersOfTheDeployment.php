<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_diff_key;
use function array_flip;
use function array_key_exists;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
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
     * Decision 0012: what reads a request object unsigned, written only by whoever declares the client.
     */
    private const string UNSIGNED_REQUEST_OBJECTS = 'request_object_signing_alg';

    /**
     * @param array<string, mixed> $members
     *
     * @return array<string, mixed> those a client may register as well
     */
    public static function without(array $members): array
    {
        return array_diff_key($members, array_flip(self::NAMES));
    }

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
        if (($members[self::UNSIGNED_REQUEST_OBJECTS] ?? null) === UnsignedRequestObjects::ALGORITHM) {
            throw new InvalidClientMetadataException(
                self::UNSIGNED_REQUEST_OBJECTS,
                $source->source(),
                sprintf(
                    'A client does not register "%s" as its request_object_signing_alg: a request object is read unsigned only for a client whoever declares it names so (decision 0012).',
                    UnsignedRequestObjects::ALGORITHM,
                ),
            );
        }
    }
}
