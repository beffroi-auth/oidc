<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidRequestException;
use function is_string;
use function preg_match;
use SensitiveParameter;
use function strcasecmp;

/**
 * An access token as a protected resource receives it: the Authorization header (RFC 6750 §2.1,
 * RFC 9449 §7.1) or the form body (RFC 6750 §2.2), never the query string (§2.3, RFC 9700 §4.3.2),
 * never both. A header of a scheme this provider does not serve is left to whoever understands it.
 *
 * The scheme comes back with the token, because a token is presented the way it was issued: one bound
 * to a key is sent under "DPoP" with a proof beside it (RFC 9449 §7.1), and whoever stole it and sends
 * it as a bearer token is refused before anything else is read.
 */
final readonly class PresentedAccessToken
{
    /**
     * RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
     */
    private const string B64TOKEN = '[A-Za-z0-9\-._~+\/]+=*';

    /**
     * RFC 9110 §11.6.1: the scheme is a token, and what follows it is not part of it. "Bearerish" is
     * another scheme, and so is one this provider does not serve; "Bearer" followed by anything but a
     * space is this scheme, sent wrong.
     */
    private const string SCHEME = '/^([!#$%&\'*+\-.^_`|~0-9A-Za-z]+)(?![!#$%&\'*+\-.^_`|~0-9A-Za-z])/';

    private const string CREDENTIALS = '/^[^ ]+ +(' . self::B64TOKEN . ')$/';

    private const string PARAMETER = '/^' . self::B64TOKEN . '$/';

    /**
     * @param string $scheme one of the schemes the resource serves, spelled as this provider spells it
     */
    public function __construct(
        public string $scheme,
        #[SensitiveParameter]
        public string $value,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the form parameters of the request body, never the query string
     * @param non-empty-list<string> $schemes what the resource reads a token under, which is what the
     *                                        provider is wired to bind tokens with
     *
     * @throws InvalidRequestException when the token is malformed or sent twice
     */
    public static function fromRequest(?string $authorizationHeader, array $parameters, array $schemes): ?self
    {
        $fromHeader = self::fromHeader($authorizationHeader, $schemes);
        $fromBody = self::fromBody($parameters);
        if ($fromHeader === null) {
            return $fromBody;
        }
        if ($fromBody !== null) {
            throw new InvalidRequestException('The access token is sent by more than one method (RFC 6750 section 2).');
        }

        return $fromHeader;
    }

    /**
     * Whether the token was presented the way a token bound like this is presented (RFC 9449 §7.1); a
     * token bound to nothing is a bearer token and is presented as one.
     */
    public function isPresentedAs(?ConfirmationInterface $confirmation): bool
    {
        return $this->scheme === ($confirmation?->scheme() ?? TokenResponse::BEARER);
    }

    /**
     * @param non-empty-list<string> $schemes
     */
    private static function fromHeader(?string $header, array $schemes): ?self
    {
        if ($header === null || preg_match(self::SCHEME, $header, $matches) !== 1) {
            return null;
        }
        $scheme = self::served($matches[1], $schemes);
        if ($scheme === null) {
            return null;
        }
        if (preg_match(self::CREDENTIALS, $header, $credentials) !== 1) {
            throw new InvalidRequestException('The Authorization header does not carry an access token (RFC 6750 section 2.1).');
        }

        return new self($scheme, $credentials[1]);
    }

    /**
     * RFC 9110 §11.6.1: a scheme is compared without regard to case, and answered in the spelling of the
     * specification that defines it.
     *
     * @param non-empty-list<string> $schemes
     */
    private static function served(string $scheme, array $schemes): ?string
    {
        foreach ($schemes as $served) {
            if (strcasecmp($scheme, $served) === 0) {
                return $served;
            }
        }

        return null;
    }

    /**
     * RFC 6750 §2.2: the body carries a bearer token and nothing else; a token bound to a key travels in
     * the header with the proof that goes with it (RFC 9449 §7.1).
     *
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

        return new self(TokenResponse::BEARER, $value);
    }
}
