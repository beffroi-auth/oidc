<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use function array_values;
use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use function sprintf;

final readonly class CodeChallengeMethods implements CodeChallengeMethodsInterface
{
    /**
     * @var non-empty-array<non-empty-string, CodeChallengeMethodInterface> by method name
     */
    private array $methods;

    /**
     * @param iterable<CodeChallengeMethodInterface> $methods
     *
     * @throws InvalidArgumentException when a name is wired twice or none is wired
     */
    public function __construct(iterable $methods)
    {
        $wired = [];
        foreach ($methods as $method) {
            $name = $method->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('The code challenge method "%s" is wired twice.', $name));
            }
            $wired[$name] = $method;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('A provider verifies a PKCE challenge with at least one method (RFC 7636 section 4.2).');
        }
        $this->methods = $wired;
    }

    public function codeChallengeMethods(): array
    {
        return array_values($this->methods);
    }

    public function codeChallengeMethodNamed(string $name): ?CodeChallengeMethodInterface
    {
        return $this->methods[$name] ?? null;
    }
}
