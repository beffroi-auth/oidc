<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_string;
use function parse_url;
use function sprintf;
use function strtolower;

/**
 * The endpoints a tenant announces in its discovery document (OIDC Discovery §3, RP-Initiated Logout §2.1,
 * RFC 8414 §2 for introspection and revocation), as absolute URLs. A relying party uses them as they are, so what is announced is checked here rather
 * than trusted: an absolute URL without a fragment (RFC 6749 §3.1, §3.2: a fragment never reaches the
 * server anyway), without credentials, over HTTPS, plain HTTP being tolerated on a loopback host only,
 * the same exception the issuer makes for development.
 *
 * The token endpoint has no exception: RFC 6749 §3.2 requires TLS there because the request carries the
 * client credentials and the response the tokens, and Symfony's oidc_login refuses a token endpoint in
 * clear even on loopback. A provider that cannot announce an HTTPS token endpoint has nothing to announce.
 * The introspection and revocation endpoints carry the client credentials and a token too, and RFC 7662
 * §2.1 and RFC 7009 §2 require TLS of them the same way.
 */
final readonly class ProviderEndpoints
{
    public string $authorization;

    public string $token;

    public string $userinfo;

    public string $jwks;

    public string $endSession;

    public string $introspection;

    public string $revocation;

    public function __construct(string $authorization, string $token, string $userinfo, string $jwks, string $endSession, string $introspection, string $revocation)
    {
        $this->authorization = self::secureUrl('authorization', $authorization, true);
        $this->token = self::secureUrl('token', $token, false);
        $this->userinfo = self::secureUrl('userinfo', $userinfo, true);
        $this->jwks = self::secureUrl('JWK Set', $jwks, true);
        $this->endSession = self::secureUrl('end session', $endSession, true);
        $this->introspection = self::secureUrl('introspection', $introspection, false);
        $this->revocation = self::secureUrl('revocation', $revocation, false);
    }

    private static function secureUrl(string $name, string $url, bool $loopbackInClear): string
    {
        $parts = parse_url($url);
        if ($parts === false || ! isset($parts['scheme'], $parts['host']) || ! is_string($parts['host'])) {
            throw new InvalidArgumentException(sprintf('The %s endpoint "%s" is not an absolute URL.', $name, $url));
        }
        if (isset($parts['fragment'])) {
            throw new InvalidArgumentException(sprintf('The %s endpoint "%s" must not carry a fragment.', $name, $url));
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException(sprintf('The %s endpoint "%s" must not carry credentials.', $name, $url));
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme === 'https') {
            return $url;
        }
        if ($loopbackInClear && $scheme === 'http' && Issuer::isLoopbackHost(strtolower($parts['host']))) {
            return $url;
        }

        throw new InvalidArgumentException($loopbackInClear
            ? sprintf('The %s endpoint "%s" must use HTTPS; plain HTTP is only accepted on a loopback host.', $name, $url)
            : sprintf('The %s endpoint "%s" must use HTTPS (RFC 6749 section 3.2), on a loopback host too.', $name, $url));
    }
}
