<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function base64_encode;
use function hash;
use function hash_equals;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function rtrim;
use SensitiveParameter;
use function sprintf;
use function strtr;

/**
 * The PKCE challenge (RFC 7636 §4.2, §4.3), matched against the verifier at the token endpoint (§4.6).
 */
final readonly class CodeChallenge
{
    private const string PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/';

    public function __construct(
        public string $value,
        public CodeChallengeMethod $method,
    ) {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf('The code challenge "%s" is not 43 to 128 unreserved characters (RFC 7636 §4.2).', $value));
        }
    }

    /**
     * RFC 7636 §4.6, compared in constant time; the syntax of the verifier (§4.1) is the caller's check.
     */
    public function verifies(#[SensitiveParameter] string $codeVerifier): bool
    {
        $computed = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        return hash_equals($this->value, $computed);
    }
}
