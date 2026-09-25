<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Token\PresentedAccessToken;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\InvalidRequestException;
use function preg_match;
use Heidi\Oidc\Port\ServedTokenSchemesInterface;
use function strcasecmp;

/**
 * How a protected resource of this provider reads the access token a request carries: the Authorization
 * header (RFC 6750 §2.1, RFC 9449 §7.1) or the form body (RFC 6750 §2.2), never the query string (§2.3,
 * RFC 9700 §4.3.2), never both. A header of a scheme this provider does not serve is left to whoever
 * understands it, and a request that carries no token at all is no error of the protocol (§3.1): the
 * resource answers it with a challenge, which is the caller's to send.
 *
 * Reading a request is what a parser of the Application does, here as at the endpoints a browser talks
 * to: the grammar of the header lives here, the body is read the one way every endpoint reads a
 * parameter, and what comes out is the value object the Domain reasons about.
 *
 * Which schemes are read is what the provider is wired to bind tokens with, asked of the wiring at every
 * request: a deployment wired for no binding reads bearer tokens alone.
 */
final readonly class PresentedAccessTokenParser
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

    public function __construct(
        private ServedTokenSchemesInterface $schemes,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization header of the request, null when it carries none
     * @param RequestParameters $parameters the form parameters of the request body, never the query string
     *
     * @throws InvalidRequestException when the token is malformed or sent twice
     *
     * @return PresentedAccessToken|null null when the request carries no token of this provider
     */
    public function parse(?string $authorizationHeader, RequestParameters $parameters): ?PresentedAccessToken
    {
        $fromHeader = $this->fromHeader($authorizationHeader);
        $fromBody = self::fromBody($parameters);
        if ($fromHeader === null) {
            return $fromBody;
        }
        if ($fromBody !== null) {
            throw new InvalidRequestException('The access token is sent by more than one method (RFC 6750 section 2).');
        }

        return $fromHeader;
    }

    private function fromHeader(?string $header): ?PresentedAccessToken
    {
        if ($header === null || preg_match(self::SCHEME, $header, $matches) !== 1) {
            return null;
        }
        $scheme = $this->served($matches[1]);
        if ($scheme === null) {
            return null;
        }
        if (preg_match(self::CREDENTIALS, $header, $credentials) !== 1) {
            throw new InvalidRequestException('The Authorization header does not carry an access token (RFC 6750 section 2.1).');
        }

        return new PresentedAccessToken($scheme, $credentials[1]);
    }

    /**
     * RFC 9110 §11.6.1: a scheme is compared without regard to case, and answered in the spelling of the
     * specification that defines it.
     */
    private function served(string $scheme): ?string
    {
        foreach ($this->schemes->servedTokenSchemes() as $served) {
            if (strcasecmp($scheme, $served) === 0) {
                return $served;
            }
        }

        return null;
    }

    /**
     * RFC 6750 §2.2: the body carries a bearer token and nothing else; a token bound to a key travels in
     * the header with the proof that goes with it (RFC 9449 §7.1).
     */
    private static function fromBody(RequestParameters $parameters): ?PresentedAccessToken
    {
        $value = $parameters->optional('access_token');
        if ($value === null) {
            return null;
        }
        if (preg_match(self::PARAMETER, $value) !== 1) {
            throw new InvalidRequestException('The access_token parameter must be a single bearer token (RFC 6750 section 2.2).');
        }

        return new PresentedAccessToken(TokenResponse::BEARER, $value);
    }
}
