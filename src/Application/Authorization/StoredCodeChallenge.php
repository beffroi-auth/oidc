<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use function explode;
use function sprintf;
use function str_contains;

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
     * @throws InvalidArgumentException
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
