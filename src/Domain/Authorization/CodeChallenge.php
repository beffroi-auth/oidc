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
 * The PKCE challenge of an authorization request (RFC 7636 §4.2, §4.3): the base64url-encoded SHA-256
 * of a verifier the client keeps. Its syntax is the one of RFC 7636 §4.2, code-challenge = 43*128unreserved;
 * whether it matches a verifier is checked at the token endpoint (RFC 7636 §4.6).
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
     * RFC 7636 §4.6: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge, compared in constant
     * time. The syntax of the verifier (§4.1) is checked by the caller before it gets here.
     */
    public function verifies(#[SensitiveParameter] string $codeVerifier): bool
    {
        $computed = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        return hash_equals($this->value, $computed);
    }
}
