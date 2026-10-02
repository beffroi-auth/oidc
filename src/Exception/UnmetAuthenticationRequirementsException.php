<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OpenID Connect Core Error Code unmet_authentication_requirements 1.0 §1: an essential "acr" the
 * provider cannot meet (OIDC Core §5.5.1.1).
 */
final class UnmetAuthenticationRequirementsException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unmet_authentication_requirements', $description, 400, true);
    }
}
