<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use SensitiveParameter;

/**
 * RFC 6750 §2.1, RFC 9449 §7.1
 */
final readonly class PresentedAccessToken
{
    /**
     * @param non-empty-string $scheme one of the schemes the resource serves, spelled as this provider spells it
     */
    public function __construct(
        public string $scheme,
        #[SensitiveParameter]
        public string $value,
    ) {
    }

    /**
     * RFC 9449 §7.1
     */
    public function isPresentedAs(?ConfirmationInterface $confirmation): bool
    {
        return $this->scheme === ($confirmation?->scheme() ?? TokenResponse::BEARER);
    }
}
