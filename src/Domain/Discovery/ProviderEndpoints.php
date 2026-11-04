<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Discovery;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_string;
use function parse_url;
use function sprintf;
use function strtolower;

/**
 * OIDC Discovery §3, RFC 8414 §2
 *
 * Only an endpoint a browser reaches may be plain HTTP on a loopback host; one a client calls never is.
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

    public string $pushedAuthorizationRequest;

    public string $deviceAuthorization;

    public string $deviceVerification;

    public string $backchannelAuthentication;

    public string $backchannelApproval;

    public string $clientRegistration;

    public function __construct(
        string $authorization,
        string $token,
        string $userinfo,
        string $jwks,
        string $endSession,
        string $introspection,
        string $revocation,
        string $pushedAuthorizationRequest,
        string $deviceAuthorization,
        string $deviceVerification,
        string $backchannelAuthentication,
        string $backchannelApproval,
        string $clientRegistration,
    ) {
        $this->authorization = self::secureUrl('authorization', $authorization, true);
        $this->token = self::secureUrl('token', $token, false);
        $this->userinfo = self::secureUrl('userinfo', $userinfo, true);
        $this->jwks = self::secureUrl('JWK Set', $jwks, true);
        $this->endSession = self::secureUrl('end session', $endSession, true);
        $this->introspection = self::secureUrl('introspection', $introspection, false);
        $this->revocation = self::secureUrl('revocation', $revocation, false);
        $this->pushedAuthorizationRequest = self::secureUrl('pushed authorization request', $pushedAuthorizationRequest, false);
        $this->deviceAuthorization = self::secureUrl('device authorization', $deviceAuthorization, false);
        $this->deviceVerification = self::secureUrl('device verification', $deviceVerification, true);
        $this->backchannelAuthentication = self::secureUrl('backchannel authentication', $backchannelAuthentication, false);
        $this->backchannelApproval = self::secureUrl('backchannel approval', $backchannelApproval, true);
        $this->clientRegistration = self::secureUrl('client registration', $clientRegistration, false);
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

        throw new InvalidArgumentException(
            $loopbackInClear
                ? sprintf('The %s endpoint "%s" must use HTTPS; plain HTTP is only accepted on a loopback host.', $name, $url)
                : sprintf(
                    'The %s endpoint "%s" must use HTTPS (RFC 6749 section 3.2, RFC 9126 section 2, RFC 8628 section 3.1, CIBA Core section 7), on a loopback host too.',
                    $name,
                    $url,
                ),
        );
    }
}
