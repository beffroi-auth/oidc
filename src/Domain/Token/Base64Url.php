<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function base64_encode;
use function rtrim;
use function strtr;

/**
 * RFC 4648 §5 without padding, as RFC 7515 §2 defines "base64url" for everything JOSE: token values,
 * "at_hash", and the identifiers that travel in a JWT.
 */
final readonly class Base64Url
{
    public static function encode(string $octets): string
    {
        return rtrim(strtr(base64_encode($octets), '+/', '-_'), '=');
    }
}
