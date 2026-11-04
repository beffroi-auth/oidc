<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Dpop;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * RFC 9449 §4.2
 *
 * Read but not verified: nothing it says is trusted yet.
 */
final readonly class DpopProof
{
    /**
     * RFC 9449 §4.1
     */
    public const string HEADER = 'DPoP';

    public const string TYPE = 'dpop+jwt';

    /**
     * RFC 7515 §4.1.3
     */
    public const string KEY = 'jwk';

    /**
     * RFC 9449 §4.2, RFC 9110 §9.1
     */
    private const string METHOD = '/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/D';

    public function __construct(
        public UnverifiedJwt $jwt,
    ) {
    }

    /**
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    public function identifier(): string
    {
        return $this->required('jti');
    }

    /**
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
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string
     */
    public function url(): string
    {
        return $this->required('htu');
    }

    /**
     * @throws InvalidDpopProofException
     */
    public function issuedAt(): DateTimeImmutable
    {
        return $this->jwt->time('iat') ?? throw new InvalidDpopProofException('A DPoP proof carries an iat (RFC 9449 section 4.2).');
    }

    /**
     * @throws InvalidDpopProofException
     *
     * @return non-empty-string|null
     */
    public function accessTokenHash(): ?string
    {
        return $this->optional('ath');
    }

    /**
     * @throws InvalidDpopProofException
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
     * @throws InvalidDpopProofException
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
