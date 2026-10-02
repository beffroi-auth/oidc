<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function hash;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use function intdiv;
use SensitiveParameter;
use function strlen;
use function substr;

/**
 * OIDC Core §3.1.3.6 "at_hash": the left-most half of the digest of the "alg", base64url encoded.
 */
final readonly class TokenHash
{
    public static function of(#[SensitiveParameter] string $value, SignatureAlgorithmInterface $algorithm): string
    {
        $digest = hash($algorithm->digestAlgorithm(), $value, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }
}
