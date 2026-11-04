<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use function array_any;
use function array_filter;
use function array_keys;
use function array_values;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\ProvingCredentialInterface;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * Decision 0010
 */
final readonly class StepUp
{
    /**
     * @var non-empty-list<AuthenticationContextClass> the requested classes still within reach, in the client's order
     */
    public array $classes;

    /**
     * @var non-empty-list<Credential&ProvingCredentialInterface> the user's credentials that would do, oldest first
     */
    public array $credentials;

    /**
     * @param list<AuthenticationContextClass> $classes
     * @param list<Credential&ProvingCredentialInterface> $credentials
     */
    public function __construct(
        public AuthenticationProofs $proofs,
        array $classes,
        array $credentials,
    ) {
        if ($classes === []) {
            throw new InvalidArgumentException('A step-up reaches at least one class.');
        }
        if ($credentials === []) {
            throw new InvalidArgumentException('A step-up is made with at least one credential of the user.');
        }
        $this->classes = $classes;
        $this->credentials = $credentials;
    }

    /**
     * Null when no credential of the user would satisfy any class, and when the session already satisfies one.
     *
     * @param list<AuthenticationContextClass> $classes requested classes the provider can prove, in the client's order
     * @param list<Credential> $credentials every credential of the user, revoked ones included
     */
    public static function towards(AuthenticationProofs $proofs, array $classes, array $credentials): ?self
    {
        if (array_any($classes, static fn (AuthenticationContextClass $class): bool => $class->isSatisfiedBy($proofs->methods()))) {
            return null;
        }
        $reachable = [];
        $able = [];
        foreach ($credentials as $credential) {
            if (! $credential instanceof ProvingCredentialInterface) {
                continue;
            }
            $methods = $credential->provableMethods();
            if ($methods === []) {
                continue;
            }
            $satisfied = self::satisfied($proofs, $methods, $classes);
            if ($satisfied === []) {
                continue;
            }
            $able[] = $credential;
            $reachable = [...$reachable, ...$satisfied];
        }
        if ($able === []) {
            return null;
        }

        return new self(
            $proofs,
            array_values(array_filter($classes, static fn (AuthenticationContextClass $class): bool => array_any($reachable, static fn (AuthenticationContextClass $reached): bool => $reached->equals($class)))),
            $able,
        );
    }

    /**
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function wouldBeMetBy(array $methods): bool
    {
        return self::satisfied($this->proofs, $methods, $this->classes) !== [];
    }

    /**
     * @return non-empty-list<string> each kind once, in the order its credentials were enrolled
     */
    public function kinds(): array
    {
        $kinds = [];
        foreach ($this->credentials as $credential) {
            $kinds[$credential->kind()] = true;
        }

        return array_keys($kinds);
    }

    /**
     * @param non-empty-list<AuthenticationMethod> $methods
     * @param list<AuthenticationContextClass> $classes
     *
     * @return list<AuthenticationContextClass>
     */
    private static function satisfied(AuthenticationProofs $proofs, array $methods, array $classes): array
    {
        $proven = [...$proofs->methods(), ...$methods];

        return array_values(array_filter($classes, static fn (AuthenticationContextClass $class): bool => $class->isSatisfiedBy($proven)));
    }
}
