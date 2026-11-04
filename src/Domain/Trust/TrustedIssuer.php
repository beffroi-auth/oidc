<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Trust;

use function array_any;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use function sprintf;

/**
 * RFC 7523 §3
 */
final readonly class TrustedIssuer
{
    /**
     * RFC 7519 §4.1.1 StringOrURI, restricted to a URI
     */
    private const string ISSUER_PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    /**
     * @var non-empty-list<non-empty-string>
     */
    public array $signingAlgorithms;

    /**
     * @var non-empty-list<string>
     */
    public array $clientIds;

    /**
     * @param list<non-empty-string> $signingAlgorithms at least one
     * @param list<string> $clientIds at least one
     * @param string $identityProvider the source of the linked identities its subjects name (decision 0002)
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $issuer,
        public ClientJwks|ClientUri $keys,
        array $signingAlgorithms,
        array $clientIds,
        public string $identityProvider,
        public Scopes $trustedScopes,
    ) {
        if (preg_match(self::ISSUER_PATTERN, $issuer) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'A trusted issuer is named by an absolute URI without a fragment, and "%s" is not one (RFC 7519 section 4.1.1).',
                $issuer,
            ));
        }
        if ($signingAlgorithms === []) {
            throw new InvalidArgumentException(sprintf('The trusted issuer "%s" signs with at least one algorithm (RFC 7515 section 4.1.1).', $issuer));
        }
        if ($clientIds === []) {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" names at least one client that may present its assertions, or nothing may be done with them (RFC 7523 section 3).',
                $issuer,
            ));
        }
        if ($identityProvider === '') {
            throw new InvalidArgumentException(sprintf(
                'The trusted issuer "%s" names the source of the identities its assertions are about (decision 0002).',
                $issuer,
            ));
        }
        $this->signingAlgorithms = $signingAlgorithms;
        $this->clientIds = $clientIds;
    }

    public function allowsClient(string $clientId): bool
    {
        return in_array($clientId, $this->clientIds, true);
    }

    public function isTrustedFor(Scopes $scopes): bool
    {
        return $this->trustedScopes->covers($scopes);
    }

    public function signsWith(string $algorithm): bool
    {
        return array_any($this->signingAlgorithms, static fn (string $trusted): bool => $trusted === $algorithm);
    }
}
