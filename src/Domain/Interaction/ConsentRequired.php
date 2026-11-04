<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Scope\Scopes;

final readonly class ConsentRequired implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthenticationSession $session,
        public Scopes $scopes,
        public ConsentRequirement $requirement,
        public ?AuthorizationDetails $authorizationDetails = null,
        public ClaimNames $claims = new ClaimNames(),
    ) {
    }

    public function name(): string
    {
        return 'consent';
    }
}
