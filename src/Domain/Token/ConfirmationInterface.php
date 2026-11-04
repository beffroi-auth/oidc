<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * RFC 7800 §3.1
 */
interface ConfirmationInterface
{
    /**
     * RFC 7800 §3.1
     */
    public const string CLAIM = 'cnf';

    /**
     * @return non-empty-string
     */
    public function member(): string;

    /**
     * The thumbprint the member carries, base64url without padding.
     */
    public function value(): string;

    /**
     * The scheme the bound token is presented with, and the "token_type" of the response (RFC 6749 §5.1).
     *
     * @return non-empty-string
     */
    public function scheme(): string;

    /**
     * @return non-empty-array<string, mixed>
     */
    public function toMembers(): array;

    /**
     * @return array<string, mixed> the "cnf" claim, to merge into a token's claims
     */
    public function toClaims(): array;

    public function matches(self $other): bool;
}
