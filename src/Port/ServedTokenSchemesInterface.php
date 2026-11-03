<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

/**
 * The schemes a protected resource of this provider reads an access token under (RFC 6750 §2.1,
 * RFC 9449 §7.1), and the ones a challenge names when a request carried no token at all (RFC 6750 §3.1).
 *
 * They are derived from what the provider binds tokens with and never listed beside it: a deployment
 * wired for no binding reads bearer tokens alone, and one wired for proof of possession says so in its
 * challenge, so that a client learns it may bind its tokens.
 */
interface ServedTokenSchemesInterface
{
    /**
     * @return non-empty-list<non-empty-string> each once, in the order the bindings are wired, the scheme of a
     *                                          token bound to nothing first
     */
    public function servedTokenSchemes(): array;
}
