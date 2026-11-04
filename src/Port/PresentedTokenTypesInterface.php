<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 8693 §3
 */
interface PresentedTokenTypesInterface
{
    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     *
     * @return non-empty-list<TokenTypeIdentifier>
     */
    public function presentedTokenTypes(): array;
}
