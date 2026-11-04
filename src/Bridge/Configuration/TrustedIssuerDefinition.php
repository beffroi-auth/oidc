<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use function array_diff;
use function array_keys;
use function array_map;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

final readonly class TrustedIssuerDefinition
{
    private const array KEYS = [
        'jwks',
        'jwks_uri',
        'signing_algorithms',
        'clients',
        'identity_provider',
        'trusted_scopes',
    ];

    private function __construct(
        public TrustedIssuer $issuer,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the keys of architecture §5.1, in snake_case
     *
     * @throws InvalidArgumentException
     */
    public static function fromArray(string $issuer, array $definition, SignatureAlgorithmsInterface $algorithms): self
    {
        $unknown = array_diff(array_keys($definition), self::KEYS);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('The trusted issuer "%s" has unknown keys: %s.', $issuer, implode(', ', $unknown)));
        }

        return new self(new TrustedIssuer(
            $issuer,
            self::publishedKeys($issuer, $definition),
            self::signingAlgorithms($issuer, $definition, $algorithms),
            self::stringList($issuer, 'clients', $definition['clients'] ?? []),
            self::text($issuer, 'identity_provider', $definition),
            self::trustedScopes($issuer, $definition),
        ));
    }

    /**
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    private static function publishedKeys(string $issuer, array $definition): ClientJwks|ClientUri
    {
        $jwks = $definition['jwks'] ?? null;
        $jwksUri = $definition['jwks_uri'] ?? null;
        if ($jwks !== null && $jwksUri !== null) {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" publishes the keys it signs with either in "jwks" or behind a "jwks_uri", never both (RFC 7517 section 5).',
                $issuer,
            ));
        }
        if ($jwks !== null) {
            if (! is_array($jwks)) {
                throw new InvalidArgumentException(sprintf('The jwks option of the trusted issuer "%s" must be a JWK Set (RFC 7517 section 5).', $issuer));
            }

            return ClientJwks::fromDocument($jwks);
        }
        if ($jwksUri === null) {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" publishes the keys it signs with in "jwks" or behind a "jwks_uri" (RFC 7517 section 5).',
                $issuer,
            ));
        }

        return new ClientUri(self::text($issuer, 'jwks_uri', $definition));
    }

    /**
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     *
     * @return non-empty-list<non-empty-string>
     */
    private static function signingAlgorithms(string $issuer, array $definition, SignatureAlgorithmsInterface $algorithms): array
    {
        $wired = AlgorithmNames::of($algorithms->all());
        $names = self::stringList($issuer, 'signing_algorithms', $definition['signing_algorithms'] ?? []);
        $trusted = [];
        foreach ($names as $name) {
            if (! in_array($name, $wired, true)) {
                throw new InvalidArgumentException(sprintf(
                    'The trusted issuer "%s" signs with "%s", which this provider does not verify; the wired algorithms are %s.',
                    $issuer,
                    $name,
                    implode(', ', $wired),
                ));
            }
            $trusted[] = $name;
        }
        if ($trusted === []) {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" names at least one signing algorithm, among %s (RFC 7515 section 4.1.1).',
                $issuer,
                implode(', ', $wired),
            ));
        }

        return $trusted;
    }

    /**
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    private static function trustedScopes(string $issuer, array $definition): Scopes
    {
        $names = self::stringList($issuer, 'trusted_scopes', $definition['trusted_scopes'] ?? []);
        if ($names === []) {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" is trusted for at least one scope, or nothing may be asked with its assertions (RFC 6749 section 3.3).',
                $issuer,
            ));
        }

        return new Scopes(array_map(static fn (string $scope): Scope => new Scope($scope), $names));
    }

    /**
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    private static function text(string $issuer, string $key, array $definition): string
    {
        $value = $definition[$key] ?? null;
        if (! is_string($value) || $value === '') {
            throw new InvalidArgumentException(sprintf('The %s option of the trusted issuer "%s" must be a non-empty string.', $key, $issuer));
        }

        return $value;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return list<string>
     */
    private static function stringList(string $issuer, string $key, mixed $value): array
    {
        $refusal = new InvalidArgumentException(sprintf('The %s option of the trusted issuer "%s" must be a list of strings.', $key, $issuer));
        if (! is_array($value)) {
            throw $refusal;
        }
        $list = [];
        foreach ($value as $item) {
            if (! is_string($item)) {
                throw $refusal;
            }
            $list[] = $item;
        }

        return $list;
    }
}
