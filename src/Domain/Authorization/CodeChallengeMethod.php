<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * RFC 7636 §4.2: how the code verifier was transformed into the challenge. Only S256 exists here: "plain"
 * is refused (RFC 7636 §4.3 lets the server do so, decision 0006 requires it), and a request without a
 * method is refused too, because RFC 7636 §4.3 would default it to "plain".
 */
enum CodeChallengeMethod: string
{
    case S256 = 'S256';
}
