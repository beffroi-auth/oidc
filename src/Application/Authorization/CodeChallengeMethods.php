<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use function array_values;
use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use function sprintf;

/**
 * The PKCE methods the wiring gave this provider, in the order they are wired (RFC 7636 §4.2). The one
 * source of truth over them: the discovery document reads this list to know what to announce, an
 * authorization request is resolved against it, and a stored challenge is read back from it. A method
 * wired twice, and a provider wired with none, are refused here, where the wiring is collected: PKCE is
 * required of every client this provider serves (decision 0006), so a provider that verifies no challenge
 * is not one it can be.
 */
final readonly class CodeChallengeMethods implements CodeChallengeMethodsInterface
{
    /**
     * @var non-empty-array<non-empty-string, CodeChallengeMethodInterface> by the name each method gives itself
     */
    private array $methods;

    /**
     * @param iterable<CodeChallengeMethodInterface> $methods at least one
     *
     * @throws InvalidArgumentException when a name is wired twice, or when nothing is wired at all
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
