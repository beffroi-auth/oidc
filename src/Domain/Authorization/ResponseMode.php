<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function in_array;

/**
 * How the authorization endpoint hands its response to the client (OAuth 2.0 Multiple Response Type
 * Encoding Practices §2.1): the parameters in the query of the redirect URI, or posted by a form the
 * user agent submits (OAuth 2.0 Form Post Response Mode §2), or, since issue #163, the same parameters
 * gathered in a JWT the tenant signs and delivered either way (JARM §2.1). The set is closed by the
 * specification; which of its cases a deployment serves is what the renderers wired into the integration
 * say, and what the discovery document announces. "fragment" belongs to the response types this provider
 * does not serve (decision 0006), so it is not here.
 */
enum ResponseMode: string
{
    case Query = 'query';

    case FormPost = 'form_post';

    case Jwt = 'jwt';

    case QueryJwt = 'query.jwt';

    case FormPostJwt = 'form_post.jwt';

    /**
     * JARM §2.1: "jwt" names no delivery of its own, it names the signed mode the response type defaults
     * to, which for "code", the only response type this provider serves (decision 0006), is "query.jwt".
     * Every other mode names itself, so that a request is judged and an answer delivered against one
     * mode and never against an alias.
     */
    public function resolved(): self
    {
        return $this === self::Jwt ? self::QueryJwt : $this;
    }

    /**
     * Whether the answer is a document the tenant signs rather than a list of parameters (JARM §2): what
     * makes the response a fourth kind of JWS, with a lifetime the retirement of a key accounts for
     * (§3.3, issue #155).
     */
    public function signsTheAnswer(): bool
    {
        return in_array($this, [self::Jwt, self::QueryJwt, self::FormPostJwt], true);
    }
}
