<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\AuthorizationResponse;

/**
 * Everything is acquired: the code is issued and the user agent goes back to the client. The interaction
 * is completed.
 */
final readonly class Granted implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthorizationCode $code,
        public AuthorizationResponse $response,
    ) {
    }
}
