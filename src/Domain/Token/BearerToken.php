<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidRequestException;
use function is_string;
use function preg_match;
use SensitiveParameter;

/**
 * A bearer token as a protected resource receives it (RFC 6750 §2): in the Authorization header with
 * the "Bearer" scheme (§2.1, the scheme compared without regard to case as RFC 9110 §11.1 requires), or as
 * the "access_token" parameter of an application/x-www-form-urlencoded body (§2.2). Never in the query
 * string (§2.3): RFC 9700 §4.3.2 advises against it, URLs end up in logs and referrers, and the
 * integration is not to hand query parameters here. Both methods at once is one request too many (§2,
 * "Clients MUST NOT use more than one method"): invalid_request.
 *
 * The token itself is the b64token of §2.1: an opaque string that a compact JWS fits. A header that
 * names the scheme without a token that fits it is malformed, invalid_request (§3.1); a header of another
 * scheme is not a bearer token at all and is left to whoever understands it.
 */
final readonly class BearerToken
{
    /**
     * RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
     */
    private const string B64TOKEN = '[A-Za-z0-9\-._~+\/]+=*';

    private const string HEADER = '/^Bearer +(' . self::B64TOKEN . ')$/i';

    /**
     * The header names the Bearer scheme when "Bearer" is not followed by another character of a scheme
     * name (tchar, RFC 9110 §5.6.2): "Bearerish" is another scheme, "Bearer" followed by anything else,
     * a token, a tab, nothing, is ours to read.
     */
    private const string SCHEME = '/^Bearer(?![!#$%&\'*+\-.^_`|~0-9A-Za-z])/i';

    private const string PARAMETER = '/^' . self::B64TOKEN . '$/';

    public function __construct(
        #[SensitiveParameter]
        public string $value,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the decoded application/x-www-form-urlencoded body, if any; never the query string
     *
     * @throws InvalidRequestException when the token is malformed or sent twice
     * @return self|null null when the request carries no bearer token
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
