<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * RFC 9449 §6.1
 */
final readonly class KeyConfirmationKind implements ConfirmationKindInterface
{
    public function member(): string
    {
        return KeyConfirmation::MEMBER;
    }

    public function scheme(): string
    {
        return KeyConfirmation::SCHEME;
    }

    public function of(string $thumbprint): ConfirmationInterface
    {
        return new KeyConfirmation($thumbprint);
    }
}
