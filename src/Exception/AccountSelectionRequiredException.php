<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6
 */
final class AccountSelectionRequiredException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('account_selection_required', $description, 400, true);
    }
}
