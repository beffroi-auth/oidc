<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\ConfirmationInterface;

/**
 * RFC 8705 §3 and RFC 9449 §7.1 "invalid_token": the access token is bound to something this request did
 * not present again, or was presented under another scheme than the one its binding calls for. Whoever
 * stole a bound token holds bytes that open nothing.
 *
 * The challenge names the scheme the binding calls for, so that a client told this much knows what to
 * send: a token bound to a key is presented under "DPoP" with a proof, and never as a bearer token.
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
