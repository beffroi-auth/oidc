<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * The defaults of a client a deployment declares, never of one that registers itself (SpecifiedDefaults).
 */
final readonly class DeploymentDefaults implements ClientMetadataSourceInterface
{
    /**
     * @var non-empty-list<string>
     */
    public const array GRANT_TYPES = ['authorization_code', 'refresh_token'];

    public const string SCOPE = 'openid profile email';

    public function source(): string
    {
        return 'the defaults of a deployment';
    }

    public function members(): array
    {
        return [
            'grant_types' => self::GRANT_TYPES,
            'scope' => self::SCOPE,
        ];
    }
}
