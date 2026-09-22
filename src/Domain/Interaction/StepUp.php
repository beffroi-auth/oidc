<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use function array_any;
use function array_filter;
use function array_keys;
use function array_values;
use Heidi\Core\Domain\Credential\Credential;
use Heidi\Core\Domain\Credential\ProvingCredentialInterface;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * Why a signed-in user is sent to the login page again (decision 0010): the client asked for classes the
 * provider can prove, the session satisfies none, and a credential of this user would; the new proof
 * joins the proofs the session keeps. Decided on what this user can still prove (architecture §4.3):
 * each credential of theirs declares the methods an authentication with it may prove
 * (ProvingCredentialInterface), and a class is within reach when those methods, added to the proofs of
 * the session, satisfy it. The page offers the kinds of credentials the user actually holds that would do.
 */
final readonly class StepUp
{
    /**
     * @var non-empty-list<AuthenticationContextClass> the requested classes a credential of the user can still satisfy, in the client's order
     */
    public array $classes;

    /**
     * @var non-empty-list<Credential&ProvingCredentialInterface> the credentials of the user each of which would satisfy one of them, oldest first
     */
    public array $credentials;

    /**
     * @param AuthenticationProofs $proofs what the session has proven
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
     * What one more authentication of this user could reach among the requested classes the provider can
     * prove; null when no credential of theirs would satisfy any, which the caller refuses or answers with
     * what the session has, and null when the session already satisfies one, there is nothing to step up to.
     *
     * @param list<AuthenticationContextClass> $classes the requested classes the provider can prove, in the client's order
     * @param list<Credential> $credentials the credentials of the user of the session, whatever their kind, revoked ones included
     */
    public static function towards(AuthenticationProofs $proofs, array $classes, array $credentials): ?self
    {
        if (array_any($classes, static fn (AuthenticationContextClass $class): bool => $class->isSatisfiedBy($proofs))) {
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
     * Whether one more login proving these methods, as one login gives them together, would satisfy a
     * class the client accepts.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function wouldBeMetBy(array $methods): bool
    {
        return self::satisfied($this->proofs, $methods, $this->classes) !== [];
    }

    /**
     * The kinds of the credentials that would do, each once, in the order they were enrolled: what the
     * page names, and nothing of a kind the user does not hold.
     *
     * @return non-empty-list<string>
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
     * The classes among the given ones that the proofs, with these methods added as one login adds them,
     * would satisfy.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     * @param list<AuthenticationContextClass> $classes
     *
     * @return list<AuthenticationContextClass>
     */
    private static function satisfied(AuthenticationProofs $proofs, array $methods, array $classes): array
    {
        foreach ($methods as $method) {
            $proofs = $proofs->with($method, $proofs->latest());
        }

        return array_values(array_filter($classes, static fn (AuthenticationContextClass $class): bool => $class->isSatisfiedBy($proofs)));
    }
}
