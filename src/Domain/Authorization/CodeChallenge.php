<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * RFC 7636 §4.2, §4.3, §4.6
 */
final readonly class CodeChallenge
{
    /**
     * RFC 7636 §4.1, §4.2
     */
    private const string PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/D';

    public function __construct(
        public string $value,
        public CodeChallengeMethodInterface $method,
    ) {
        if (! self::hasTheShape($value)) {
            throw new InvalidArgumentException(sprintf('The code challenge "%s" is not 43 to 128 unreserved characters (RFC 7636 §4.2).', $value));
        }
    }

    /**
     * RFC 7636 §4.1, §4.2
     */
    public static function hasTheShape(#[SensitiveParameter] string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }

    /**
     * RFC 7636 §4.6
     *
     * The syntax of the verifier (§4.1) is the caller's to check.
     */
    public function verifies(#[SensitiveParameter] string $codeVerifier): bool
    {
        return $this->method->verifies($this->value, $codeVerifier);
    }
}
