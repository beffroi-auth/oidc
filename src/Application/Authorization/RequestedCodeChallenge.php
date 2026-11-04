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
 * RFC 7636 §4.3, §4.4.1
 */
final readonly class RequestedCodeChallenge
{
    public function __construct(
        private CodeChallengeMethodsInterface $methods,
    ) {
    }

    /**
     * An absent method is "plain" for RFC 7636 §4.3: it is refused, never read as the first method wired.
     *
     * @throws InvalidRequestException
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
