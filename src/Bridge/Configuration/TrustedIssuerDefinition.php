<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_diff;
use function array_keys;
use function array_map;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Key\AlgorithmNames;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Trust\TrustedIssuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

/**
 * One trusted issuer as the configuration declares it (architecture §5.1), read strictly, nothing cast. It is
 * validated at boot, so a tenant that declares an issuer it cannot read, an algorithm nothing verifies or a
 * client that does not exist learns it when the deployment starts and not when an assertion arrives.
 *
 * The keys are declared inline. A set behind a URL is a fetch and a cache of its own, keyed by the issuer and
 * not by a client, which is what federation needs and which no tenant declaring the issuers it trusts by hand
 * needs today.
 */
final readonly class TrustedIssuerDefinition
{
    private const array KEYS = [
        'jwks',
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
     * @param SignatureAlgorithmsInterface $algorithms what the provider verifies a signature with: an issuer is trusted to sign with those names and no other
     *
     * @throws InvalidArgumentException when the declaration does not hold together
     */
    public static function fromArray(string $issuer, array $definition, SignatureAlgorithmsInterface $algorithms): self
    {
        $unknown = array_diff(array_keys($definition), self::KEYS);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('The trusted issuer "%s" has unknown keys: %s.', $issuer, implode(', ', $unknown)));
        }

        return new self(new TrustedIssuer(
            $issuer,
            self::jwks($issuer, $definition),
            self::signingAlgorithms($issuer, $definition, $algorithms),
            self::stringList($issuer, 'clients', $definition['clients'] ?? []),
            self::text($issuer, 'identity_provider', $definition),
            self::trustedScopes($issuer, $definition),
        ));
    }

    /**
     * RFC 7517 §5: the keys the tenant trusts this issuer by, inline. Public keys only, which ClientJwks is
     * the invariant behind.
     *
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    private static function jwks(string $issuer, array $definition): ClientJwks
    {
        $jwks = $definition['jwks'] ?? null;
        if (! is_array($jwks)) {
            throw new InvalidArgumentException(sprintf('The trusted issuer "%s" publishes the keys it signs with in "jwks" (RFC 7517 section 5).', $issuer));
        }

        return ClientJwks::fromDocument($jwks);
    }

    /**
     * RFC 7515 §4.1.1: what an assertion of this issuer may be signed with, among the algorithms the provider
     * is wired with. An algorithm nothing verifies is refused at boot rather than at the first assertion, and
     * a deployment that drops an algorithm from its wiring drops it from every issuer with it.
     *
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
     * RFC 6749 §3.3: what this issuer is trusted for, at least one scope; an issuer trusted for none could ask
     * for nothing, so a declaration that names none is a declaration of nothing.
     *
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
