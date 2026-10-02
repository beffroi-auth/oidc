<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The types of token the exchange is wired to read (RFC 8693 §3). What a client may register in its
 * "subject_token_types" is read here, where a registration meets the wiring, so a deployment that wires no
 * reader for a type cannot register a client for it.
 */
interface PresentedTokenTypesInterface
{
    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     *
     * @return non-empty-list<TokenTypeIdentifier> in the order they are wired
     */
    public function presentedTokenTypes(): array;
}
