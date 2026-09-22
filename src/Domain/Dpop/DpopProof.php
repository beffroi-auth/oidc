<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Dpop;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * A proof of possession as a client sends it (RFC 9449 §4.2), read but not yet verified: a JWS whose
 * header carries the public key it is signed with, and whose claims name the request it was made for.
 *
 * Nothing here is trusted. What the proof says of itself is read strictly, because a proof is the one
 * thing a request brings that nobody else vouches for; whether it was signed by the key it carries is
 * the verifier's, and whether what it names is this request is the validator's.
 */
final readonly class DpopProof
{
    /**
     * RFC 9449 §4.1: the header field a proof travels in, and §4.2, the "typ" that tells it from every
     * other JWT a client signs, so that one is never taken for another (RFC 8725 §3.11).
     */
    public const string HEADER = 'DPoP';

    public const string TYPE = 'dpop+jwt';

    /**
     * RFC 7515 §4.1.3: the public key of the pair the proof is signed with.
     */
    public const string KEY = 'jwk';

    /**
     * RFC 9449 §4.2 "htm": a method token of RFC 9110 §9.1.
     */
    private const string METHOD = '/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/D';

    public function __construct(
        public UnverifiedJwt $jwt,
    ) {
    }

    /**
     * RFC 9449 §4.2 "jti": what tells one proof from the next, so that one is used once.
     *
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    public function identifier(): string
    {
        return $this->required('jti');
    }

    /**
     * RFC 9449 §4.2 "htm": the method of the request the proof was made for.
     *
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    public function method(): string
    {
        $method = $this->required('htm');
        if (preg_match(self::METHOD, $method) !== 1) {
            throw new InvalidDpopProofException('The htm of a DPoP proof is an HTTP method (RFC 9449 section 4.2).');
        }

        return $method;
    }

    /**
     * RFC 9449 §4.2 "htu": the URL of the endpoint the proof was made for, which the provider compares
     * with the one it publishes and never with what a proxy wrote in a header.
     *
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    public function url(): string
    {
        return $this->required('htu');
    }

    /**
     * RFC 9449 §4.2 "iat": when the client made the proof, which bounds how long it may be used.
     *
     * @throws InvalidDpopProofException
     */
    public function issuedAt(): DateTimeImmutable
    {
        return $this->jwt->time('iat') ?? throw new InvalidDpopProofException('A DPoP proof carries an iat (RFC 9449 section 4.2).');
    }

    /**
     * RFC 9449 §4.2 "ath": the access token the proof accompanies, named by the base64url of its
     * SHA-256, so that a proof made for one request cannot be presented with another token (§7.1).
     *
     * @throws InvalidDpopProofException when it is there and is not a string
     *
     * @return non-empty-string|null null when the proof accompanies no access token
     */
    public function accessTokenHash(): ?string
    {
        return $this->optional('ath');
    }

    /**
     * RFC 9449 §8: the nonce this provider handed the client, when it asks for one.
     *
     * @throws InvalidDpopProofException when it is there and is not a string
     *
     * @return non-empty-string|null
     */
    public function nonce(): ?string
    {
        return $this->optional('nonce');
    }

    /**
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    private function required(string $name): string
    {
        return $this->optional($name) ?? throw new InvalidDpopProofException(sprintf('A DPoP proof carries a %s (RFC 9449 section 4.2).', $name));
    }

    /**
     * @throws InvalidDpopProofException when the claim is there and is not a non-empty string
     *
     * @return non-empty-string|null
     */
    private function optional(string $name): ?string
    {
        $value = $this->jwt->claims[$name] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_string($value) || $value === '') {
            throw new InvalidDpopProofException(sprintf('The %s of a DPoP proof is a non-empty string (RFC 9449 section 4.2).', $name));
        }

        return $value;
    }
}
