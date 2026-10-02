<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Trust;

use function array_any;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use function sprintf;

/**
 * A third party whose signature a tenant trusts (RFC 7523 §3): whoever holds its signing key can name a user
 * of that tenant and be answered with an access token, so what it may do is written down in full and nothing
 * about it is inferred.
 *
 * Everything here is a closed list. The keys are the ones the tenant put in the registration, and no key a
 * token names is ever read (RFC 8725 §3.10). The algorithms are the ones it signs with, so a key of one kind
 * cannot be used with another. The clients are the ones that may present its assertions, because an issuer
 * trusted for a gateway is not thereby trusted for every client of the tenant. The scopes are what it is
 * trusted for, which the scopes of a response are a subset of. And the subjects of its assertions name users
 * through linked identities of one source (decision 0002), so an assertion never invents a row.
 *
 * It belongs to the tenant that registered it and is looked up under that tenant: an issuer one tenant trusts
 * is unknown to another, which is what keeps one deployment's trust from being another's.
 */
final readonly class TrustedIssuer
{
    /**
     * RFC 7519 §4.1.1: an "iss" is a StringOrURI, and one naming a party whose keys a tenant holds is a URI;
     * it is compared byte for byte, as every other name this provider registers.
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
     * @param string $issuer the "iss" of the assertions this issuer signs (RFC 7523 §3), compared byte for byte
     * @param ClientJwks $keys the public keys the tenant trusts this issuer by
     * @param list<non-empty-string> $signingAlgorithms the "alg" an assertion of this issuer may carry, at least one
     * @param list<string> $clientIds the clients that may present an assertion of this issuer, at least one
     * @param string $identityProvider the source of the linked identities the subjects of its assertions name (decision 0002)
     * @param Scopes $trustedScopes what this issuer is trusted for, which the scopes of a response are a subset of
     *
     * @throws InvalidArgumentException when the registration does not hold together
     */
    public function __construct(
        public string $issuer,
        public ClientJwks $keys,
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

    /**
     * RFC 7523 §3: which clients may present an assertion of this issuer, compared byte for byte.
     */
    public function allowsClient(string $clientId): bool
    {
        return in_array($clientId, $this->clientIds, true);
    }

    /**
     * What this issuer is trusted for: the scopes of a response are a subset of these, of what the client
     * registered and of what the request asked for.
     */
    public function isTrustedFor(Scopes $scopes): bool
    {
        return $this->trustedScopes->covers($scopes);
    }

    /**
     * Whether the signature of an assertion may carry this algorithm (RFC 7515 §4.1.1), among the ones the
     * tenant trusts this issuer to sign with.
     */
    public function signsWith(string $algorithm): bool
    {
        return array_any($this->signingAlgorithms, static fn (string $trusted): bool => $trusted === $algorithm);
    }
}
