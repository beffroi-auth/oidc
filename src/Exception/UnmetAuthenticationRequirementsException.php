<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * "unmet_authentication_requirements" (OpenID Connect Core Error Code unmet_authentication_requirements
 * 1.0 §1): the client asked for the "acr" claim as an essential claim with values the provider cannot
 * meet, which OIDC Core §5.5.1.1 has the provider treat as a failed authentication. Always sent back to
 * the client, whatever the prompt: it is not a login the user could do.
 */
final class UnmetAuthenticationRequirementsException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unmet_authentication_requirements', $description, 400, true);
    }
}
