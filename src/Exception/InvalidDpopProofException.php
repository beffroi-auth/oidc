<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Throwable;

/**
 * RFC 9449 §5 and §7.1 "invalid_dpop_proof": the proof the request carried cannot be read, is not signed
 * by the key it carries, or does not name this request. Never redirected: a proof is verified at an
 * endpoint that answers the client directly, and what it fails to prove says nothing of where a refusal
 * should go. A protected resource answers the same code with the challenge of §7.1.
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
