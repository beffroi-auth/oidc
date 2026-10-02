<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * OAuth 2.0 Form Post Response Mode §2: the answer of the authorization endpoint handed to the user agent
 * as a form it posts to the redirect URI, so that no parameter of the response ever sits in a URL, in an
 * address bar, in a history or in an access log. What the page is made of is fixed here, in the module,
 * because the Content-Security-Policy is part of the answer: the one script that submits the form is
 * named by its hash, which lets the page refuse every other script instead of allowing inline scripts at
 * large. The words around the button are the integration's, the script is not.
 */
final readonly class FormPostResponse
{
    /**
     * What submits the form where the user agent runs scripts. Its text is a constant because the hash
     * of the policy is computed from it: change one byte here and the page stops running its own script.
     */
    public const string SCRIPT = 'document.forms[0].submit();';

    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters the response as the protocol names it, "iss" included (RFC 9207 §2)
     */
    public function __construct(
        public RedirectUri $redirectUri,
        array $parameters,
    ) {
        if ($parameters === []) {
            throw new InvalidArgumentException('A form post response carries at least one parameter (Form Post Response Mode section 2).');
        }
        $this->parameters = $parameters;
    }

    /**
     * CSP Level 3 §6.6.2.2 "hash-source", over the text of the script element.
     */
    public function scriptHash(): string
    {
        return new InlineScript(self::SCRIPT)->cspHashSource();
    }

    /**
     * Nothing loads, nothing frames, the one script is named, and the form posts to the registered
     * redirect URI and nowhere else (CSP Level 3 §6.1, §6.3.2).
     */
    public function contentSecurityPolicy(): string
    {
        return sprintf(
            "default-src 'none'; script-src '%s'; form-action %s; base-uri 'none'; frame-ancestors 'none'",
            $this->scriptHash(),
            $this->redirectUri->origin,
        );
    }
}
