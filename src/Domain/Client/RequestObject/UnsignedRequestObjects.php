<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\RequestObject;

/**
 * A client that registered "request_object_signing_alg": "none" (OIDC Registration §2): its request
 * objects carry no signature and are read all the same. The named and bounded exception of decision
 * 0006, and the one way an unsigned object is read instead of being refused unread: it is registered per
 * client, never a switch of the deployment, and a client that registered it is not a FAPI client.
 *
 * What such an object may decide is what the query would have decided anyway. The destination is not
 * among them: the redirect URI is matched against the registration of the client byte for byte (RFC 6749
 * §3.1.2.3), so an unsigned object chooses the transport and never the address.
 */
final readonly class UnsignedRequestObjects implements RequestObjectSigningInterface
{
    /**
     * RFC 7515 §4.1.1, RFC 7518 §3.6: the "alg" of a JWS with no signature.
     */
    public const string ALGORITHM = 'none';

    public function accepts(?string $algorithm, array $wired): bool
    {
        return $algorithm === self::ALGORITHM;
    }

    public function acceptsUnsigned(): bool
    {
        return true;
    }

    public function needsPublishedKeys(): bool
    {
        return false;
    }
}
