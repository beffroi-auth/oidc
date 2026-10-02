<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * Binding to the key the client proved possession of (RFC 9449 §6.1). The token is presented under the
 * "DPoP" scheme from then on, and every request that carries it carries a proof signed with that key.
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
