<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * RFC 7591 §2
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
