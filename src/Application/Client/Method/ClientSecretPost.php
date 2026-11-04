<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;

/**
 * RFC 6749 §2.3.1
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
