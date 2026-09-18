<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The successful answer of the authorization endpoint (RFC 6749 §4.1.2), always with "iss" (RFC 9207 §2).
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

    public function toUri(): string
    {
        return $this->redirectUri->withParameters($this->parameters());
    }
}
