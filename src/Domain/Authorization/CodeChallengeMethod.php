<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * RFC 7636 §4.2. S256 only: "plain", and the absence that defaults to it (§4.3), are refused (decision 0006).
 */
enum CodeChallengeMethod: string
{
    case S256 = 'S256';
}
