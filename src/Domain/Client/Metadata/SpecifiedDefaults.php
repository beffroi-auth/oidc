<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * What RFC 7591 §2 says a client that registered nothing about it is registered for: the authorization code
 * grant alone, the "code" response type that goes with it, and "client_secret_basic" at the endpoints that
 * authenticate a client.
 *
 * A client that registers itself takes these and never the convenience of a deployment (DeploymentDefaults):
 * what it did not ask for is what the specification says it gets, so that the same request registers the
 * same client whatever this deployment would have written for itself.
 */
final readonly class SpecifiedDefaults implements ClientMetadataSourceInterface
{
    public function source(): string
    {
        return 'the defaults of RFC 7591 section 2';
    }

    public function members(): array
    {
        return [
            'grant_types' => ['authorization_code'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ];
    }
}
