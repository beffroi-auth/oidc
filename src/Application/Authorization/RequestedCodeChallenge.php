<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;

/**
 * What the "code_challenge" and "code_challenge_method" parameters of an authorization request must be
 * (RFC 7636 §4.3, §4.4.1): S256 and nothing else (decision 0006), which is what the token endpoint will
 * verify the code verifier against.
 */
final readonly class RequestedCodeChallenge
{
    /**
     * A client exempted by decision 0008 may send no challenge; one it sends is checked like any other
     * (RFC 9700 §2.1.1).
     *
     * @throws InvalidRequestException when a challenge is missing, of another method, or malformed
     */
    public static function of(Client $client, ?string $challenge, ?string $method): ?CodeChallenge
    {
        if ($challenge === null && $method === null && ! $client->registration->requiresPkce) {
            return null;
        }
        if ($challenge === null) {
            throw new InvalidRequestException('The code_challenge parameter is missing (RFC 7636 section 4.3).', true);
        }
        if ($method !== CodeChallengeMethod::S256->value) {
            throw new InvalidRequestException('The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).', true);
        }
        try {
            return new CodeChallenge($challenge, CodeChallengeMethod::S256);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException('The code_challenge parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.2).', true);
        }
    }
}
