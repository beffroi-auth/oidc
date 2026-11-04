<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function sprintf;

/**
 * RFC 6749 §4.1.2.1, RFC 9207 §2
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
     * @throws LogicException when the error is not redirectable
     */
    public static function fromException(RedirectTarget $target, OAuth2Exception $exception): self
    {
        if (! $exception->redirectable) {
            throw new LogicException(sprintf(
                'The error "%s" is not redirectable: it is shown to the user, never sent to the client (RFC 6749 §4.1.2.1).',
                $exception->error,
            ));
        }

        return new self($target->client->tenant->issuer, $target->redirectUri, $target->state, $exception->error, $exception->errorDescription);
    }

    /**
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
}
