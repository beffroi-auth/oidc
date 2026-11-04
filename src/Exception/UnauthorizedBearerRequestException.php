<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use function sprintf;

/**
 * RFC 6750 §3.1
 *
 * Reads the same whatever gave the credential away (decision 0006).
 */
abstract class UnauthorizedBearerRequestException extends OAuth2Exception
{
    public const string SCHEME = 'Bearer';

    public function __construct(string $description)
    {
        parent::__construct('invalid_token', $description, 401, false);
    }

    /**
     * RFC 6750 §3
     *
     * The descriptions of this package carry no double quote nor backslash, so nothing is escaped.
     */
    public function challenge(): string
    {
        return sprintf('%s error="%s", error_description="%s"', self::SCHEME, $this->error, $this->errorDescription);
    }
}
