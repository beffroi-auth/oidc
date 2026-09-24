<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Oidc\Domain\Token\Base64Url;
use function hash;
use function hash_equals;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * The PKCE challenge (RFC 7636 §4.2, §4.3), matched against the verifier at the token endpoint (§4.6).
 */
final readonly class CodeChallenge
{
    /**
     * RFC 7636 §4.1 and §4.2 give the verifier and the challenge one production, 43*128unreserved: the
     * challenge is the base64url of a digest, the verifier is what the client drew, and both are read
     * against this. It is written here, where the challenge lives, and the token endpoint asks rather
     * than writing it again.
     */
    private const string PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/';

    public function __construct(
        public string $value,
        public CodeChallengeMethod $method,
    ) {
        if (! self::hasTheShape($value)) {
            throw new InvalidArgumentException(sprintf('The code challenge "%s" is not 43 to 128 unreserved characters (RFC 7636 §4.2).', $value));
        }
    }

    /**
     * Whether a value is 43 to 128 unreserved characters, which a challenge is (RFC 7636 §4.2) and a
     * verifier is (§4.1).
     */
    public static function hasTheShape(#[SensitiveParameter] string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }

    /**
     * RFC 7636 §4.6, compared in constant time; the syntax of the verifier (§4.1) is the caller's check.
     */
    public function verifies(#[SensitiveParameter] string $codeVerifier): bool
    {
        $computed = Base64Url::encode(hash('sha256', $codeVerifier, true));

        return hash_equals($this->value, $computed);
    }
}
