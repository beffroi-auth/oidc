<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * The name of what an authorization request may ask for (RFC 6749 §3.1.1, OIDC Core §3.1.2.1): a code, and
 * nothing else. Decision 0006 admits no implicit flow and no hybrid one, so this is a name the
 * specifications and that decision fix rather than the wiring, as the two names of ResponseModeNames are:
 * there is no list of response types anywhere and nothing tagged to gain one.
 *
 * It is read by the request that carries a response type, by the registration that names the ones a client
 * asks for (RFC 7591 §2 "response_types") and by the document that announces them, and written here only.
 */
final readonly class ResponseTypeNames
{
    /**
     * RFC 6749 §4.1: the authorization code flow, the only one this provider answers.
     */
    public const string CODE = 'code';
}
