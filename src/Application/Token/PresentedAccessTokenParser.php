<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Token\PresentedAccessToken;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\InvalidRequestException;
use function preg_match;
use Beffroi\Oidc\Port\ServedTokenSchemesInterface;
use function strcasecmp;

/**
 * RFC 6750 §2.1, §2.2, RFC 9449 §7.1
 *
 * Never from the query string (RFC 9700 §4.3.2).
 */
final readonly class PresentedAccessTokenParser
{
    /**
     * RFC 6750 §2.1
     */
    private const string B64TOKEN = '[A-Za-z0-9\-._~+\/]+=*';

    /**
     * RFC 9110 §11.6.1
     *
     * "Bearer" followed by anything but a space is this scheme sent wrong, not another scheme.
     */
    private const string SCHEME = '/^([!#$%&\'*+\-.^_`|~0-9A-Za-z]+)(?![!#$%&\'*+\-.^_`|~0-9A-Za-z])/';

    private const string CREDENTIALS = '/^[^ ]+ +(' . self::B64TOKEN . ')$/D';

    private const string PARAMETER = '/^' . self::B64TOKEN . '$/D';

    public function __construct(
        private ServedTokenSchemesInterface $schemes,
    ) {
    }

    /**
     * @param RequestParameters $parameters the form parameters of the request body, never the query string
     *
     * @throws InvalidRequestException when the token is malformed or sent twice
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
     * RFC 9110 §11.6.1
     *
     * @return non-empty-string|null
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
     * RFC 6750 §2.2
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
