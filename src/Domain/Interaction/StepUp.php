<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use function array_any;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;

/**
 * Why a signed-in user is sent to the login page again (decision 0010): the client asked for classes the
 * provider can prove and the session satisfies none. The page reads which of its ways of signing in would
 * do; the new proof joins the proofs the session keeps.
 */
final readonly class StepUp
{
    /**
     * @param AuthenticationProofs $proofs what the session has proven
     * @param non-empty-list<AuthenticationContextClass> $classes the requested classes the provider can prove, in the client's order
     */
    public function __construct(
        public AuthenticationProofs $proofs,
        public array $classes,
    ) {
    }

    /**
     * Whether one more login proving these methods, as one login gives them together, would satisfy a
     * class the client accepts.
     *
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function wouldBeMetBy(array $methods): bool
    {
        $proofs = $this->proofs;
        foreach ($methods as $method) {
            $proofs = $proofs->with($method, $proofs->latest());
        }

        return array_any($this->classes, static fn (AuthenticationContextClass $class): bool => $class->isSatisfiedBy($proofs));
    }
}
