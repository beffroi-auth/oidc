<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Discovery;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * OIDC Discovery §3, RFC 8414 §2
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
     * @param array<string, mixed> $members
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public Issuer $issuer,
        private array $members,
        public int $maxAge,
    ) {
        self::assertCacheLifetime($maxAge);
        $this->headers = [
            'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
        ];
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function assertCacheLifetime(int $maxAge): void
    {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
    }

    /**
     * OIDC Discovery §4.1
     */
    public function openIdConfigurationUrl(): string
    {
        return $this->issuer->value . self::OPENID_CONFIGURATION_PATH;
    }

    /**
     * RFC 8414 §3
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
