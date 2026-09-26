<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\Scope\Scopes;

/**
 * Send the user to the consent page, which calls grantConsent() or deny(). It carries what the page shows:
 * the scopes of the request, and the authorization details the request asks for beyond them (RFC 9396 §2),
 * which is the part a user reads rather than recognises.
 */
final readonly class ConsentRequired implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthenticationSession $session,
        public Scopes $scopes,
        public ConsentRequirement $requirement,
        public ?AuthorizationDetails $authorizationDetails = null,
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
