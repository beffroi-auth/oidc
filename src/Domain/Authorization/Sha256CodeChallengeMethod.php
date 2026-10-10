<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use function hash;
use function hash_equals;
use Beffroi\Core\Domain\Encoding\Base64Url;
use SensitiveParameter;

/**
 * RFC 7636 §4.2: BASE64URL(SHA256(ASCII(code_verifier))), the transformation RFC 9700 §2.1.1 holds every
 * client to and the one this provider is wired with (decision 0006).
 */
final readonly class Sha256CodeChallengeMethod implements CodeChallengeMethodInterface
{
    public const string NAME = 'S256';

    public function name(): string
    {
        return self::NAME;
    }

    public function verifies(string $challenge, #[SensitiveParameter] string $codeVerifier): bool
    {
        return hash_equals($challenge, Base64Url::encode(hash('sha256', $codeVerifier, true)));
    }
}
