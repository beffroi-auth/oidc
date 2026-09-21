<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use DateTimeImmutable;
use function is_int;
use function is_string;

/**
 * A client assertion as it arrived (RFC 7523 §2.2, OIDC Core §9): the compact JWS, its protected header
 * and its claims, read before anything is verified. Nothing it says is trusted at this point; it is read
 * to know which client claims to send it and which key is supposed to have signed it, and the claims are
 * judged only once the signature has been.
 */
final readonly class ClientAssertion
{
    /**
     * RFC 7523 §2.2: the one value of "client_assertion_type".
     */
    public const string TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public string $compact,
        public array $protectedHeader,
        public array $claims,
    ) {
    }

    /**
     * RFC 7515 §4.1.1.
     */
    public function algorithm(): ?string
    {
        $alg = $this->protectedHeader['alg'] ?? null;

        return is_string($alg) && $alg !== '' ? $alg : null;
    }

    /**
     * RFC 7515 §4.1.4; a client that publishes one key alone may send none.
     */
    public function keyId(): ?string
    {
        $kid = $this->protectedHeader['kid'] ?? null;

        return is_string($kid) && $kid !== '' ? $kid : null;
    }

    public function claim(string $name): ?string
    {
        $value = $this->claims[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * RFC 7519 §2: a numeric date is a number of seconds since the epoch, and nothing else is read as one.
     */
    public function time(string $name): ?DateTimeImmutable
    {
        $value = $this->claims[$name] ?? null;

        return is_int($value) ? (new DateTimeImmutable('@' . $value)) : null;
    }

    /**
     * RFC 7519 §4.1.3: one string, or an array of them.
     *
     * @return list<string>
     */
    public function audiences(): array
    {
        $audience = $this->claims['aud'] ?? null;
        if (is_string($audience)) {
            return [$audience];
        }
        $audiences = [];
        foreach ((array) $audience as $value) {
            if (is_string($value)) {
                $audiences[] = $value;
            }
        }

        return $audiences;
    }
}
