<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 7800 §3.1
 */
interface ConfirmationKindInterface
{
    /**
     * @return non-empty-string
     */
    public function member(): string;

    /**
     * The scheme a token bound this way is presented with, and the "token_type" of the response (RFC 6749 §5.1).
     *
     * @return non-empty-string
     */
    public function scheme(): string;

    /**
     * @throws InvalidArgumentException
     */
    public function of(string $thumbprint): ConfirmationInterface;
}
