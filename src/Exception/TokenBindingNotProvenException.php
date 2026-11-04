<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\ConfirmationInterface;

/**
 * RFC 8705 §3, RFC 9449 §7.1
 *
 * The challenge names the scheme the binding calls for.
 */
final class TokenBindingNotProvenException extends OAuth2Exception implements ChallengeInterface
{
    public function __construct(
        string $description,
        private readonly ConfirmationInterface $confirmation,
    ) {
        parent::__construct('invalid_token', $description, 401, false);
    }

    public function challengeScheme(): string
    {
        return $this->confirmation->scheme();
    }

    public function challengeHeaders(): array
    {
        return [];
    }
}
