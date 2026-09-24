<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * The metadata of a tenant (OIDC Discovery §3, RFC 8414 §2): one document, two well-known locations.
 *
 * It says what the provider does and nothing it does not (decision 0006), and it is not assembled here:
 * each specification the provider implements contributes its own members (MetadataContributorInterface),
 * so a capability that arrives is a class beside the others rather than an edit of this one. What the
 * document holds is therefore exactly what the wiring contributes, in the order it is wired.
 */
final readonly class ProviderMetadata
{
    public const string CONTENT_TYPE = 'application/json';

    public const string OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

    public const string AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param array<string, mixed> $members what the contributors put in the document, in order
     * @param int $maxAge how long a client may keep the document, in seconds
     *
     * @throws InvalidArgumentException when the lifetime is not a number of seconds
     */
    public function __construct(
        public Issuer $issuer,
        private array $members,
        public int $maxAge,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
        $this->headers = [
            'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
        ];
    }

    /**
     * OIDC Discovery §4.1: appended to the issuer, path included.
     */
    public function openIdConfigurationUrl(): string
    {
        return $this->issuer->value . self::OPENID_CONFIGURATION_PATH;
    }

    /**
     * RFC 8414 §3: inserted between the host and the path of the issuer.
     */
    public function authorizationServerMetadataUrl(): string
    {
        return $this->issuer->origin() . self::AUTHORIZATION_SERVER_METADATA_PATH . $this->issuer->path;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->members;
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->members);
    }
}
