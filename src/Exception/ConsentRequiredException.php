<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "consent_required": the request said prompt=none and no consent covers it. Always
 * sent back to the client.
 */
final class ConsentRequiredException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('consent_required', $description, 400, true);
    }
}
