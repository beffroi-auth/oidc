<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidRequestException;
use function is_string;
use function preg_match;
use SensitiveParameter;

/**
 * A bearer token as a protected resource receives it (RFC 6750 §2): the Authorization header (§2.1) or
 * the form body (§2.2), never the query string (§2.3, RFC 9700 §4.3.2), never both. A header of another
 * scheme is left to whoever understands it.
 */
final readonly class BearerToken
{
    /**
     * RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
     */
    private const string B64TOKEN = '[A-Za-z0-9\-._~+\/]+=*';

    private const string HEADER = '/^Bearer +(' . self::B64TOKEN . ')$/i';

    /**
     * "Bearer" not followed by another tchar (RFC 9110 §5.6.2): "Bearerish" is another scheme.
     */
    private const string SCHEME = '/^Bearer(?![!#$%&\'*+\-.^_`|~0-9A-Za-z])/i';

    private const string PARAMETER = '/^' . self::B64TOKEN . '$/';

    public function __construct(
        #[SensitiveParameter]
        public string $value,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body, never the query string
     *
     * @throws InvalidRequestException when the token is malformed or sent twice
     */
    public static function fromRequest(?string $authorizationHeader, array $parameters): ?self
    {
        $fromHeader = self::fromHeader($authorizationHeader);
        $fromBody = self::fromBody($parameters);
        if ($fromHeader === null) {
            return $fromBody;
        }
        if ($fromBody !== null) {
            throw new InvalidRequestException('The access token is sent by more than one method (RFC 6750 section 2).');
        }

        return $fromHeader;
    }

    private static function fromHeader(?string $header): ?self
    {
        if ($header === null || preg_match(self::SCHEME, $header) !== 1) {
            return null;
        }
        if (preg_match(self::HEADER, $header, $matches) !== 1) {
            throw new InvalidRequestException('The Authorization header does not carry a bearer token (RFC 6750 section 2.1).');
        }

        return new self($matches[1]);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private static function fromBody(array $parameters): ?self
    {
        $value = $parameters['access_token'] ?? '';
        if ($value === '') {
            return null;
        }
        if (! is_string($value) || preg_match(self::PARAMETER, $value) !== 1) {
            throw new InvalidRequestException('The access_token parameter must be a single bearer token (RFC 6750 section 2.2).');
        }

        return new self($value);
    }
}
