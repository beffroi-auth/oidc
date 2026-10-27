<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * What a response of the token endpoint needs from outside the provider, read before the grant spends what the
 * request presented (architecture §4.5): what its access token is struck with (AddressedAccessToken) and, when it
 * carries an ID token, what that token is struck with (AddressedIdToken). The key of the tenant each is signed with
 * and the salt of the tenant a pairwise "sub" is computed with are opened by the KMS, and the key of the client an
 * ID token is encrypted to is read from what the client publishes, so any of them answering late is an error the
 * same request is served past, where read after the spending it would cost the client its code, or the family of
 * its refresh token.
 */
final readonly class AddressedResponse
{
    /**
     * @param AddressedIdToken|null $idToken null for a response that carries no ID token
     */
    public function __construct(
        public AddressedAccessToken $accessToken,
        public ?AddressedIdToken $idToken = null,
    ) {
    }
}
