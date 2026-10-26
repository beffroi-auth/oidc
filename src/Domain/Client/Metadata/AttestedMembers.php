<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_diff_key;
use function array_flip;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;

/**
 * The members of a software statement an authority the tenant pinned signed (RFC 7591 §2.3), once the
 * signature has been verified and never before.
 *
 * RFC 7591 §3.1.1 puts it in front of the members the client sent: what a statement says of a member
 * takes precedence over the same member sent in the clear, which is what makes the `client_name` and the
 * `logo_uri` of an attested client the ones an authority signed rather than the ones the caller typed.
 * That is the whole of the precedence rule, and it lives in the order of the sources rather than in
 * anything that reads them.
 *
 * What it carries is the claims of the statement that are client metadata, and the registered claims of
 * RFC 7519 §4.1 are not: "iss" says who signed, "exp" until when, and neither describes a client. They
 * are dropped here rather than refused by the reader, because a statement that carries them is a
 * statement of the ordinary shape and not a registration with unknown keys.
 *
 * Those members are held to what a client registers: a member of this provider alone is refused here as
 * it is refused of the body (`MembersOfTheDeployment`), a statement saying what the client is and never
 * what it may have (decision 0009). What a statement signed is kept among what the client sent, so a member
 * let through here would be read back from that row as one the client sent, and refused there.
 */
final readonly class AttestedMembers implements ClientMetadataSourceInterface
{
    /**
     * RFC 7519 §4.1: what a statement carries about itself rather than about the client it describes.
     *
     * @var list<string>
     */
    private const array ABOUT_THE_STATEMENT = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * @var array<string, mixed>
     */
    private array $members;

    /**
     * @param array<string, mixed> $claims the claims of the verified statement, as its issuer signed them
     *
     * @throws InvalidClientMetadataException when the statement carries a member of this provider alone
     */
    public function __construct(array $claims)
    {
        $this->members = array_diff_key($claims, array_flip(self::ABOUT_THE_STATEMENT));
        MembersOfTheDeployment::refuseIn($this);
    }

    public function source(): string
    {
        return 'the software statement its issuer signed';
    }

    public function members(): array
    {
        return $this->members;
    }
}
