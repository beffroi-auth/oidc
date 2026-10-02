<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use function implode;
use function sprintf;

/**
 * What the "code_challenge" and "code_challenge_method" parameters of an authorization request must be
 * (RFC 7636 §4.3, §4.4.1): a challenge made with a method the provider is wired with and nothing else,
 * which is what the token endpoint will verify the code verifier against. The methods are asked of the
 * wiring and never of a name written here, so that what a request may name is what the discovery document
 * announces; decision 0006 wires "S256" alone.
 */
final readonly class RequestedCodeChallenge
{
    public function __construct(
        private CodeChallengeMethodsInterface $methods,
    ) {
    }

    /**
     * A client exempted by decision 0008 may send no challenge; one it sends is checked like any other
     * (RFC 9700 §2.1.1). A request that names no method names none: RFC 7636 §4.3 reads the absence as
     * "plain", so it is refused as "plain" is, and never read as the first method wired.
     *
     * @throws InvalidRequestException when a challenge is missing, of a method nothing wired answers to,
     *                                 or malformed
     */
    public function of(Client $client, ?string $challenge, ?string $method): ?CodeChallenge
    {
        if ($challenge === null && $method === null && ! $client->registration->requiresPkce) {
            return null;
        }
        if ($challenge === null) {
            throw new InvalidRequestException('The code_challenge parameter is missing (RFC 7636 section 4.3).', true);
        }
        $wired = $method === null ? null : $this->methods->codeChallengeMethodNamed($method);
        if ($wired === null) {
            throw new InvalidRequestException(sprintf(
                'The code_challenge_method parameter must be %s (RFC 7636 section 4.3).',
                implode(' or ', AlgorithmNames::of($this->methods->codeChallengeMethods())),
            ), true);
        }
        try {
            return new CodeChallenge($challenge, $wired);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException('The code_challenge parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.2).', true);
        }
    }
}
