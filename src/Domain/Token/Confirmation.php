<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function hash_equals;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_string;

/**
 * What an access token is bound to (RFC 7800 §3.1): the "cnf" claim of an "at+jwt", the "cnf" member of
 * an introspection response (RFC 8705 §3.2), and what a resource of the provider asks the caller to
 * present again. A token that carries none is a bearer token, honoured by whoever holds it.
 *
 * One kind of confirmation today, the certificate the client presented at the handshake, named by the
 * SHA-256 thumbprint of its DER encoding (RFC 8705 §3.1).
 */
final readonly class Confirmation
{
    public const string CLAIM = 'cnf';

    public const string CERTIFICATE_THUMBPRINT = 'x5t#S256';

    private function __construct(
        /**
         * The "x5t#S256" of RFC 8705 §3.1, base64url without padding.
         */
        public string $certificateThumbprint,
    ) {
        if ($certificateThumbprint === '') {
            throw new InvalidArgumentException('A confirmation names the certificate it binds a token to (RFC 8705 section 3.1).');
        }
    }

    public static function ofCertificate(ClientCertificate $certificate): self
    {
        return new self($certificate->x5tS256());
    }

    /**
     * The claims of a token as they were written, read strictly: a "cnf" that is not an object, or that
     * names nothing this provider binds to, is a token this provider did not issue.
     *
     * @param array<array-key, mixed> $claims
     */
    public static function fromClaims(array $claims): ?self
    {
        $confirmation = $claims[self::CLAIM] ?? null;
        if ($confirmation === null) {
            return null;
        }

        return self::fromMembers(is_array($confirmation) ? $confirmation : []);
    }

    /**
     * The members of a "cnf", however they were kept: read strictly, because a confirmation nobody can
     * read is a token bound to nothing.
     *
     * @param array<array-key, mixed> $members
     */
    public static function fromMembers(array $members): self
    {
        $thumbprint = $members[self::CERTIFICATE_THUMBPRINT] ?? null;
        if (! is_string($thumbprint) || $thumbprint === '') {
            throw new InvalidArgumentException('The "cnf" of an access token of this provider names the thumbprint of a certificate (RFC 8705 section 3.1).');
        }

        return new self($thumbprint);
    }

    /**
     * @return array<string, mixed> the "cnf" claim, to merge into the claims of a token or into the
     *                              members of an introspection response
     */
    public function toClaims(): array
    {
        return [
            self::CLAIM => [
                self::CERTIFICATE_THUMBPRINT => $this->certificateThumbprint,
            ],
        ];
    }

    /**
     * RFC 8705 §3: whether the certificate presented with a request is the one the token is bound to. A
     * request made without a certificate never matches, so a token that was bound cannot be replayed as
     * a bearer token by whoever stole it.
     */
    public function isPresentedBy(?ClientCertificate $certificate): bool
    {
        return $certificate !== null && hash_equals($this->certificateThumbprint, $certificate->x5tS256());
    }
}
