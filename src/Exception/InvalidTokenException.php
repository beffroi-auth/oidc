<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\TokenResponse;
use Throwable;

/**
 * RFC 6750 §3.1, RFC 9449 §7.2
 *
 * Reads the same whatever gave the token away (decision 0006). Its scheme is Bearer until the resource that read
 * the request calls presentedUnder().
 */
final class InvalidTokenException extends OAuth2Exception implements ChallengeInterface
{
    /**
     * @param non-empty-string $scheme the scheme the token was presented under, spelled as this provider spells it
     */
    public function __construct(
        string $description,
        ?Throwable $previous = null,
        private readonly string $scheme = TokenResponse::BEARER,
    ) {
        parent::__construct('invalid_token', $description, 401, false, $previous);
    }

    public static function notIssuedHere(?Throwable $previous = null): self
    {
        return new self('The access token is not an access token issued by this provider.', $previous);
    }

    public static function expired(): self
    {
        return new self('The access token expired.');
    }

    /**
     * RFC 8707 §2
     *
     * @param non-empty-string $scheme
     */
    public static function addressedElsewhere(string $scheme): self
    {
        return new self('The access token is addressed to a resource of its own and not to this provider (RFC 8707 section 2).', null, $scheme);
    }

    /**
     * @param non-empty-string $scheme
     */
    public function presentedUnder(string $scheme): self
    {
        return new self($this->errorDescription, $this, $scheme);
    }

    public function challengeScheme(): string
    {
        return $this->scheme;
    }

    public function challengeHeaders(): array
    {
        return [];
    }
}
