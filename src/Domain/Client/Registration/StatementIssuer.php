<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use function array_any;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;

/**
 * An authority whose software statements a tenant accepts in place of a credential it issued itself
 * (RFC 7591 §2.3). It is what makes the attested mode the one of decision 0009 that crosses the boundary
 * of an organisation: an initial access token is a secret this provider issues, keeps, counts and revokes
 * for every team that integrates, and a statement moves the proof to a party the tenant pins, the
 * provider issuing nothing.
 *
 * The keys are the ones the tenant wrote down, and **no key a statement names is ever read** (RFC 8725
 * §3.10): a statement verified against a key it carries itself proves that whoever wrote it holds a key,
 * which is what anybody holds. The algorithms are the ones it signs with, so a key of one kind cannot be
 * used with another.
 *
 * It belongs to the policy of the tenant that pinned it: an authority one tenant trusts is unknown to
 * another, and a tenant that pins none has the mode closed rather than open to whoever signs.
 */
final readonly class StatementIssuer
{
    /**
     * RFC 7519 §4.1.1: an "iss" is a StringOrURI, and one naming a party whose keys a tenant holds is a
     * URI; it is compared byte for byte, as every other name this provider registers.
     */
    private const string ISSUER_PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    /**
     * @var non-empty-list<non-empty-string>
     */
    public array $signingAlgorithms;

    /**
     * @param string $issuer the "iss" of the statements this authority signs, compared byte for byte
     * @param ClientJwks $keys the public keys the tenant pinned it by
     * @param list<non-empty-string> $signingAlgorithms the "alg" a statement of this authority may carry, at least one
     *
     * @throws InvalidArgumentException when the anchor does not hold together
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

    /**
     * Whether the signature of a statement may carry this algorithm (RFC 7515 §4.1.1), among the ones the
     * tenant pinned this authority to sign with.
     */
    public function signsWith(string $algorithm): bool
    {
        return array_any($this->signingAlgorithms, static fn (string $pinned): bool => $pinned === $algorithm);
    }
}
