<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * OAuth 2.0 Form Post Response Mode §2
 */
final readonly class FormPostResponse
{
    public const string SCRIPT = 'document.forms[0].submit();';

    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters "iss" included
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
     * CSP Level 3 §6.6.2.2
     */
    public function scriptHash(): string
    {
        return new InlineScript(self::SCRIPT)->cspHashSource();
    }

    /**
     * CSP Level 3 §6.1, §6.3.2
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
