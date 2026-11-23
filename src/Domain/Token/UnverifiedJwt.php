<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function array_key_exists;
use DateTimeImmutable;
use function is_int;
use function is_string;

final readonly class UnverifiedJwt
{
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
     * RFC 7515 §4.1.1
     *
     * @return non-empty-string|null
     */
    public function algorithm(): ?string
    {
        $alg = $this->protectedHeader['alg'] ?? null;

        return is_string($alg) && $alg !== '' ? $alg : null;
    }

    /**
     * RFC 7515 §4.1.4
     *
     * @return non-empty-string|null
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

        return is_int($value) ? new DateTimeImmutable('@' . $value) : null;
    }

    /**
     * RFC 7519 §4.1.5
     *
     * A JWT without "nbf" has started; one whose "nbf" is not a numeric date never starts.
     */
    public function startsAfter(DateTimeImmutable $instant): bool
    {
        if (! array_key_exists('nbf', $this->claims)) {
            return false;
        }
        $notBefore = $this->time('nbf');

        return $notBefore === null || $notBefore > $instant;
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @return list<string> none when "aud" is neither a string nor a list of strings
     */
    public function audiences(): array
    {
        return TokenAudience::valuesOf($this->claims['aud'] ?? null) ?? [];
    }
}
