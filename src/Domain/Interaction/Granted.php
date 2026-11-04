<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\AuthorizationResponse;

final readonly class Granted implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthorizationCode $code,
        public AuthorizationResponse $response,
    ) {
    }

    public function name(): string
    {
        return 'granted';
    }
}
