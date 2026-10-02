<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;

/**
 * "client_secret_post" (RFC 6749 §2.3.1): the identifier and the secret in the request body. The
 * specification only allows it for clients that cannot use the Authorization header, and the provider
 * takes it from the clients that registered it and from no other.
 */
final readonly class ClientSecretPost extends HashedSecretMethod
{
    public function name(): string
    {
        return 'client_secret_post';
    }

    public function mechanism(): string
    {
        return 'the client_secret parameter';
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        if ($request->secret() === null) {
            return null;
        }
        $clientId = $request->clientId();
        if ($clientId === null) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                null,
                $this->name(),
                'The client_secret parameter requires a client_id parameter.',
            );
        }

        return $clientId;
    }

    protected function presentedSecret(ClientAuthenticationRequest $request): ?string
    {
        return $request->secret();
    }
}
