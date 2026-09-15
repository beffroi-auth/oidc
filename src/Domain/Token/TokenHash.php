<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function hash;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use function intdiv;
use SensitiveParameter;
use function strlen;
use function substr;

/**
 * OIDC Core §3.1.3.6 "at_hash" (and §3.3.2.11 "c_hash", built the same way): the hash of the ASCII
 * octets of the value with the digest of the "alg" of the ID token, of which the left-most half is kept
 * and base64url encoded. For RS256: SHA-256, the first 128 bits, 22 characters.
 */
final readonly class TokenHash
{
    public static function of(#[SensitiveParameter] string $value, SignatureAlgorithm $algorithm): string
    {
        $digest = hash($algorithm->digestAlgorithm(), $value, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }
}
