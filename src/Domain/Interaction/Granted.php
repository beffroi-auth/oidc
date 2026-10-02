<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\AuthorizationResponse;

/**
 * The code is issued and the user agent goes back to the client.
 */
final readonly class Granted implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthorizationCode $code,
        public AuthorizationResponse $response,
    ) {
    }

    /**
     * The name of this decision, which the integration answers by sending the user agent back to the client.
     */
    public function name(): string
    {
        return 'granted';
    }
}
