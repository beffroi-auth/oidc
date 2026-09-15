<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The successful answer of the authorization endpoint (RFC 6749 §4.1.2, OIDC Core §3.1.2.5): the code,
 * "state" when the request carried one, and always "iss" (RFC 9207 §2), in the query component of the
 * redirect URI. The code is the only secret that ever travels through the user agent; it lives 60 seconds
 * and is bound to the client by PKCE (architecture §4.4).
 */
final readonly class AuthorizationResponse
{
    public function __construct(
        public Issuer $issuer,
        public RedirectUri $redirectUri,
        public ?string $state,
        #[SensitiveParameter]
        public string $code,
    ) {
        if ($code === '') {
            throw new InvalidArgumentException('An authorization response carries a code.');
        }
    }

    /**
     * The parameters of the response, in the order they are written.
     *
     * @return non-empty-array<string, string>
     */
    public function parameters(): array
    {
        $parameters = [
            'code' => $this->code,
        ];
        if ($this->state !== null) {
            $parameters['state'] = $this->state;
        }
        $parameters['iss'] = (string) $this->issuer;

        return $parameters;
    }

    /**
     * The URI the user agent is sent to (RFC 6749 §4.1.2).
     */
    public function toUri(): string
    {
        return $this->redirectUri->withParameters($this->parameters());
    }
}
