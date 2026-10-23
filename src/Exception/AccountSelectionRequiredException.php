<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "account_selection_required": the End-User is required to select a session at the
 * Authorization Server, and the provider could not have it select one, an upstream identity provider answering for
 * the person it holds a session of, ForceAuthn notwithstanding (beffroi/saml S-58).
 */
final class AccountSelectionRequiredException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('account_selection_required', $description, 400, true);
    }
}
