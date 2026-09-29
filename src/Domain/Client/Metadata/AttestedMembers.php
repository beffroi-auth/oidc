<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Metadata;

use function array_diff_key;
use function array_flip;

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
     */
    public function __construct(array $claims)
    {
        $this->members = array_diff_key($claims, array_flip(self::ABOUT_THE_STATEMENT));
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
