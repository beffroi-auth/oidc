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
 * The endpoints of a tenant (OIDC Discovery §3, RP-Initiated Logout §2.1, RFC 8414 §2, RFC 8628 §3.1, CIBA Core §4):
 * absolute, no fragment, no credentials, HTTPS with plain HTTP on a loopback host only. The endpoints a
 * client reaches server to server have no exception (RFC 6749 §3.2, RFC 7662 §2.1, RFC 7009 §2,
 * RFC 9126 §2, RFC 8628 §3.1, CIBA Core §7); the ones a browser reaches keep the loopback one, which is what a
 * deployment is developed on.
 *
 * The page where a user types a device code is one of them (RFC 8628 §3.2 "verification_uri"): it is per
 * tenant like every other, the answer of the device authorization endpoint carries it, and it is read here
 * rather than written down a second time. The page where a user answers a request made for them on the
 * back channel is one of them for the same reason (CIBA Core §7), even though no answer of the protocol
 * ever carries it: what reaches the user says where to go, and where that is, is read here. Which of these
 * the document announces is each contributor's business and not this one's.
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
