<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use function array_diff;
use function array_keys;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

/**
 * One authority whose software statements a tenant accepts, as the configuration declares it (RFC 7591
 * §2.3, architecture §5.1), read strictly, nothing cast. It is validated at boot, so a tenant that
 * declares an authority it cannot read or an algorithm nothing verifies learns it when the deployment
 * starts and not when a registration arrives.
 *
 * The keys are declared inline, as a trusted issuer's are: a set behind a URL is a fetch and a cache of
 * its own, and reading one to verify the statement that names it is the outbound request decision 0006
 * does not make.
 */
final readonly class StatementIssuerDefinition
{
    private const array KEYS = ['jwks', 'signing_algorithms'];

    private function __construct(
        public StatementIssuer $issuer,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the keys of architecture §5.1, in snake_case
     * @param SignatureAlgorithmsInterface $algorithms what the provider verifies a signature with: an authority signs with those names and no other
     *
     * @throws InvalidArgumentException when the declaration does not hold together
     */
    public static function fromArray(string $issuer, array $definition, SignatureAlgorithmsInterface $algorithms): self
    {
        $unknown = array_diff(array_keys($definition), self::KEYS);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf(
                'The software statement issuer "%s" has unknown keys: %s.',
                $issuer,
                implode(', ', $unknown),
            ));
        }

        return new self(new StatementIssuer(
            $issuer,
            self::jwks($issuer, $definition),
            self::signingAlgorithms($issuer, $definition, $algorithms),
        ));
    }

    /**
     * RFC 7517 §5: the keys the tenant pinned this authority by, inline. Public keys only, which
     * ClientJwks is the invariant behind.
     *
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     */
    private static function jwks(string $issuer, array $definition): ClientJwks
    {
        $jwks = $definition['jwks'] ?? null;
        if (! is_array($jwks)) {
            throw new InvalidArgumentException(sprintf(
                'The software statement issuer "%s" publishes the keys it signs with in "jwks" (RFC 7517 section 5).',
                $issuer,
            ));
        }

        return ClientJwks::fromDocument($jwks);
    }

    /**
     * RFC 7515 §4.1.1: what a statement of this authority may be signed with, among the algorithms the
     * provider is wired with. An algorithm nothing verifies is refused at boot rather than at the first
     * registration, and a deployment that drops an algorithm from its wiring drops it from every authority
     * with it.
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
        $value = $definition['signing_algorithms'] ?? [];
        $refusal = new InvalidArgumentException(sprintf(
            'The signing_algorithms option of the software statement issuer "%s" must be a list of strings.',
            $issuer,
        ));
        if (! is_array($value)) {
            throw $refusal;
        }
        $pinned = [];
        foreach ($value as $name) {
            if (! is_string($name) || $name === '') {
                throw $refusal;
            }
            if (! in_array($name, $wired, true)) {
                throw new InvalidArgumentException(sprintf(
                    'The software statement issuer "%s" signs with "%s", which this provider does not verify; the wired algorithms are %s.',
                    $issuer,
                    $name,
                    implode(', ', $wired),
                ));
            }
            $pinned[] = $name;
        }
        if ($pinned === []) {
            throw new InvalidArgumentException(sprintf(
                'The software statement issuer "%s" names at least one signing algorithm, among %s (RFC 7515 section 4.1.1).',
                $issuer,
                implode(', ', $wired),
            ));
        }

        return $pinned;
    }
}
