<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

/**
 * A document the provider signs for a client, under the member of OIDC Registration §2 or JARM §3 that names its
 * algorithm.
 */
final readonly class SignedDocument
{
    private function __construct(
        public string $member,
        public string $documents,
        public ResponseFormat $format,
    ) {
    }

    /**
     * @return list<self> the ID tokens, the authorization responses and the UserInfo responses of the client
     */
    public static function of(ClientRegistration $registration): array
    {
        return [
            new self('id_token_signed_response_alg', 'ID tokens', $registration->idToken),
            new self('authorization_signed_response_alg', 'authorization responses', $registration->authorizationResponse),
            new self('userinfo_signed_response_alg', 'UserInfo responses', $registration->userInfo),
        ];
    }
}
