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
 * RFC 7591 §2.3
 *
 * The keys are inline only: fetching a set to verify the statement that names it is an outbound request
 * decision 0006 refuses.
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
     *
     * @throws InvalidArgumentException
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
