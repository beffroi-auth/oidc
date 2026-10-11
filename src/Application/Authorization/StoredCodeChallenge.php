<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use function explode;
use function sprintf;
use function str_contains;

/**
 * The value a column holds a PKCE challenge as (RFC 7636 §4.3): "method:challenge", one value, because a
 * challenge may be absent (decision 0008) and two columns that are null together are one column.
 *
 * The method is written under the name it gives itself and read back as the class the wiring holds for
 * that name, which is why this is a use case and not a method of the challenge: a challenge this
 * deployment is not wired to verify is refused rather than guessed, exactly as the algorithm of a stored
 * hash is (decision 0002).
 */
final readonly class StoredCodeChallenge
{
    private const string SEPARATOR = ':';

    public function __construct(
        private CodeChallengeMethodsInterface $methods,
    ) {
    }

    public function document(CodeChallenge $challenge): string
    {
        return $challenge->method->name() . self::SEPARATOR . $challenge->value;
    }

    /**
     * @throws InvalidArgumentException when the value does not read "method:challenge", when nothing wired
     *                                 carries the method it names, or when what it carries is not a
     *                                 challenge
     */
    public function of(string $value): CodeChallenge
    {
        if (! str_contains($value, self::SEPARATOR)) {
            throw new InvalidArgumentException(sprintf('A stored code challenge reads "method:challenge", got "%s".', $value));
        }
        [$name, $challenge] = explode(self::SEPARATOR, $value, 2);
        $method = $this->methods->codeChallengeMethodNamed($name);
        if ($method === null) {
            throw new InvalidArgumentException(sprintf('The code challenge method "%s" is not one of the provider.', $name));
        }

        return new CodeChallenge($challenge, $method);
    }
}
