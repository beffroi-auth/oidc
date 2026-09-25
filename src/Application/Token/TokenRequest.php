<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Exception\InvalidRequestException;
use function is_string;
use function sprintf;

/**
 * The form parameters of a token request (RFC 6749 §3.2), read with the rules of §3.1: empty is omitted,
 * repeated or nested is refused. The client credentials are read by the ClientAuthenticator.
 */
final readonly class TokenRequest
{
    /**
     * @param array<string, mixed> $parameters
     */
    public function __construct(
        private array $parameters,
    ) {
    }

    /**
     * @throws InvalidRequestException when the parameter is missing, empty, or not a single string
     */
    public function required(string $name): string
    {
        $value = $this->optional($name);
        if ($value === null) {
            throw new InvalidRequestException(sprintf('The %s parameter is missing.', $name));
        }

        return $value;
    }

    /**
     * A parameter a specification allows to be sent several times (RFC 8707 §2), read as the browser
     * endpoints read one: a failure here is never redirectable, this endpoint answering in JSON.
     *
     * @throws InvalidRequestException when the parameter is neither a string nor a list of them
     *
     * @return list<string> empty when the request carries none
     */
    public function repeated(string $name): array
    {
        return RequestParameters::repeated($this->parameters, $name, false);
    }

    /**
     * @throws InvalidRequestException when the parameter is not a single string
     */
    public function optional(string $name): ?string
    {
        $value = $this->parameters[$name] ?? '';
        if ($value === '') {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidRequestException(sprintf('The %s parameter must be a single string.', $name));
        }

        return $value;
    }
}
