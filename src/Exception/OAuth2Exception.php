<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use function preg_match;
use RuntimeException;
use function sprintf;
use Throwable;

/**
 * A protocol error as the client will read it (RFC 6749 §4.1.2.1, §5.2, OIDC Core §3.1.2.6). The
 * descriptions are constants of this package; no internal message ever reaches "error_description".
 */
abstract class OAuth2Exception extends RuntimeException implements ExceptionInterface
{
    /**
     * RFC 6749 §5.2: ASCII without double quote nor backslash.
     */
    private const string DESCRIPTION_PATTERN = '/^[\x20\x21\x23-\x5B\x5D-\x7E]+$/D';

    /**
     * @param Throwable|null $previous for the logs; it never reaches the client
     */
    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
        public readonly int $statusCode,
        public readonly bool $redirectable,
        ?Throwable $previous = null,
    ) {
        self::assertDescription($errorDescription);
        parent::__construct(sprintf('%s: %s', $error, $errorDescription), 0, $previous);
    }

    /**
     * What an "error_description" may be. A description that becomes one later is held to it where it is written
     * (ClientAuthenticationFailure), so that it is refused by a test of what writes it rather than by the endpoint
     * that would answer with it.
     */
    public static function assertDescription(string $description): void
    {
        if (preg_match(self::DESCRIPTION_PATTERN, $description) !== 1) {
            throw new InvalidArgumentException(sprintf('The error description "%s" is not the ASCII text RFC 6749 §5.2 allows.', $description));
        }
    }
}
