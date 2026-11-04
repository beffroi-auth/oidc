<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * What a token response needs from outside the provider, read before the grant spends what the request presented,
 * so that a KMS or a client answering late costs the client neither its code nor its refresh token family.
 */
final readonly class AddressedResponse
{
    public function __construct(
        public AddressedAccessToken $accessToken,
        public ?AddressedIdToken $idToken = null,
    ) {
    }
}
