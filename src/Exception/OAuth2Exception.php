<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use function preg_match;
use RuntimeException;
use function sprintf;
use Throwable;

/**
 * A protocol error, as the client will read it (RFC 6749 §4.1.2.1 and §5.2, OIDC Core §3.1.2.6). It carries
 * the "error" code, a fixed "error_description" written for the client, the HTTP status the token endpoint
 * answers with, and whether the authorization endpoint may send it back to the redirect URI (only once the
 * client and the redirect URI have been validated, RFC 6749 §4.1.2.1). No PHP exception and no internal
 * message ever reaches "error_description": the descriptions are constants of this package.
 */
abstract class OAuth2Exception extends RuntimeException implements ExceptionInterface
{
    /**
     * RFC 6749 §5.2: error_description is ASCII text without double quotes nor backslashes
     * (%x20-21 / %x23-5B / %x5D-7E).
     */
    private const string DESCRIPTION_PATTERN = '/^[\x20\x21\x23-\x5B\x5D-\x7E]+$/';

    /**
     * @param Throwable|null $previous the cause, for the logs; it never reaches the client
     */
    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
        public readonly int $statusCode,
        public readonly bool $redirectable,
        ?Throwable $previous = null,
    ) {
        if (preg_match(self::DESCRIPTION_PATTERN, $errorDescription) !== 1) {
            throw new InvalidArgumentException(sprintf('The error description "%s" is not the ASCII text RFC 6749 §5.2 allows.', $errorDescription));
        }
        parent::__construct(sprintf('%s: %s', $error, $errorDescription), 0, $previous);
    }
}
