<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * What a deployment means when it declares a client and writes nothing: the browser flow and the renewal
 * that goes with it, and the three scopes an application of a relying party comes for. It is a convenience
 * of this provider and not the specification's, which is why it is a source of its own, read behind the
 * declaration and never by a client that registers itself (SpecifiedDefaults).
 *
 * The configuration tree names the same values, so that a deployment reading the reference sees what it
 * gets; it reads them here, there being one place they are written.
 */
final readonly class DeploymentDefaults implements ClientMetadataSourceInterface
{
    /**
     * @var non-empty-list<string>
     */
    public const array GRANT_TYPES = ['authorization_code', 'refresh_token'];

    /**
     * RFC 6749 §3.3, OIDC Core §5.4: what an application that signs a user in asks for.
     */
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
