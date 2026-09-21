<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 and RFC 9101 §6.3 "invalid_request_uri": the "request_uri" of the authorization
 * request names nothing this provider still holds. A reference nobody ever issued, one that has expired,
 * one already used and one pushed by another client all read the same, because none of them says
 * anything to whoever presents it (decision 0006); what happened is in the audit trail.
 */
final class InvalidRequestUriException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('invalid_request_uri', $description, 400, false);
    }
}
