<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use function array_any;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;

/**
 * RFC 7591 §2.3
 *
 * A statement is verified with the keys the tenant pinned, never with a key it names itself (RFC 8725 §3.10).
 */
final readonly class StatementIssuer
{
    /**
     * RFC 7519 §4.1.1, a URI rather than any StringOrURI
     */
    private const string ISSUER_PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    /**
     * @var non-empty-list<non-empty-string>
     */
    public array $signingAlgorithms;

    /**
     * @param list<non-empty-string> $signingAlgorithms at least one
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $issuer,
        public ClientJwks $keys,
        array $signingAlgorithms,
    ) {
        if (preg_match(self::ISSUER_PATTERN, $issuer) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The issuer of a software statement is named by an absolute URI without a fragment, and "%s" is not one (RFC 7519 section 4.1.1).',
                $issuer,
            ));
        }
        if ($signingAlgorithms === []) {
            throw new InvalidArgumentException(sprintf(
                'The software statement issuer "%s" signs with at least one algorithm (RFC 7515 section 4.1.1).',
                $issuer,
            ));
        }
        $this->signingAlgorithms = $signingAlgorithms;
    }

    public function signsWith(string $algorithm): bool
    {
        return array_any($this->signingAlgorithms, static fn (string $pinned): bool => $pinned === $algorithm);
    }
}
