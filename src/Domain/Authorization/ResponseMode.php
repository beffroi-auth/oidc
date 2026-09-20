<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * How the authorization endpoint hands its response to the client (OAuth 2.0 Multiple Response Type
 * Encoding Practices §2.1): the parameters in the query of the redirect URI, or posted by a form the
 * user agent submits (OAuth 2.0 Form Post Response Mode §2). The set is closed by the specification;
 * which of its cases a deployment serves is what the renderers wired into the integration say, and what
 * the discovery document announces. "fragment" belongs to the response types this provider does not
 * serve (decision 0006), so it is not here.
 */
enum ResponseMode: string
{
    case Query = 'query';

    case FormPost = 'form_post';
}
