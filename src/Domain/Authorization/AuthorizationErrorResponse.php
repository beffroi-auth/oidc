<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function sprintf;

/**
 * An error sent back to the client (RFC 6749 §4.1.2.1): "error" and "error_description" in the query
 * component of the redirect URI, "state" when the request carried one, and always "iss" (RFC 9207 §2),
 * so that a client talking to several providers can tell which one answered. The query the client
 * registered is kept (RFC 6749 §3.1.2); a registered URI never has a fragment.
 *
 * Built only from a redirectable error: an error raised before the client and its redirect URI were
 * validated is shown to the user and never comes here (RFC 9700 §4.1).
 */
final readonly class AuthorizationErrorResponse
{
    public function __construct(
        public Issuer $issuer,
        public RedirectUri $redirectUri,
        public ?string $state,
        public string $error,
        public string $errorDescription,
    ) {
    }

    /**
     * @throws LogicException when the error is one that must be shown to the user
     */
    public static function fromException(RedirectTarget $target, OAuth2Exception $exception): self
    {
        if (! $exception->redirectable) {
            throw new LogicException(sprintf('The error "%s" is not redirectable: it is shown to the user, never sent to the client (RFC 6749 §4.1.2.1).', $exception->error));
        }

        return new self($target->client->tenant->issuer, $target->redirectUri, $target->state, $exception->error, $exception->errorDescription);
    }

    /**
     * The parameters of the response, in the order they are written.
     *
     * @return non-empty-array<string, string>
     */
    public function parameters(): array
    {
        $parameters = [
            'error' => $this->error,
            'error_description' => $this->errorDescription,
        ];
        if ($this->state !== null) {
            $parameters['state'] = $this->state;
        }
        $parameters['iss'] = (string) $this->issuer;

        return $parameters;
    }

    /**
     * The URI the user agent is sent to (RFC 6749 §4.1.2.1).
     */
    public function toUri(): string
    {
        return $this->redirectUri->withParameters($this->parameters());
    }
}
