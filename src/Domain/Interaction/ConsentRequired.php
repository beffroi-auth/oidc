<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Scope\Scopes;

/**
 * Send the user to the consent page, which calls grantConsent() or deny(). It carries what the page shows:
 * the scopes of the request, the authorization details the request asks for beyond them (RFC 9396 §2),
 * which is the part a user reads rather than recognises, and the claims it asks for by name that no scope
 * of it stands for (OIDC Core §5.5).
 */
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

    /**
     * The name of this decision, which the integration answers with its consent page.
     */
    public function name(): string
    {
        return 'consent';
    }
}
