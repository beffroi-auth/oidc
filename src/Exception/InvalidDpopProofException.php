<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Throwable;

/**
 * RFC 9449 §5, §7.1
 */
final class InvalidDpopProofException extends OAuth2Exception implements ChallengeInterface
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_dpop_proof', $description, 400, false, $previous);
    }

    public function challengeScheme(): string
    {
        return KeyConfirmation::SCHEME;
    }

    public function challengeHeaders(): array
    {
        return [];
    }
}
