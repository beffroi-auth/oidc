<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationContextPolicy;
use Heidi\Core\Domain\Session\AuthenticationSession;
use function is_string;

/**
 * What a request says about the "acr" of the ID token (OIDC Core §3.1.2.1, §5.5.1.1): the "acr" claim
 * request of "claims.id_token" first, "acr_values" as the voluntary form otherwise. A value that is not
 * a string names no class and matches none; a name the policy of the tenant does not declare neither
 * (decision 0010).
 */
final readonly class AuthenticationContextRequest
{
    /**
     * @param list<string|int|float|bool> $values in order of preference
     */
    public function __construct(
        public array $values = [],
        public bool $essential = false,
    ) {
    }

    public static function of(AuthorizationRequest $request): self
    {
        $claim = $request->claims?->idToken['acr'] ?? null;
        if ($claim === null) {
            return new self($request->acrValues);
        }

        return new self($claim->values ?? ($claim->value === null ? [] : [$claim->value]), $claim->essential);
    }

    /**
     * Any class of the session will do.
     */
    public function namesNoClass(): bool
    {
        return $this->values === [];
    }

    /**
     * Whether the request binds the provider to a class (OIDC Core §5.5.1.1): it does when it is
     * essential and names one, and only then is a class the session does not satisfy a refusal. A
     * voluntary request is never refused, and an essential one that names nothing asks for no class in
     * particular.
     */
    public function demandsAClass(): bool
    {
        return $this->essential && ! $this->namesNoClass();
    }

    /**
     * The requested values that are classes of the policy, in the client's order of preference.
     *
     * @return list<AuthenticationContextClass>
     */
    public function classesOf(AuthenticationContextPolicy $policy): array
    {
        $classes = [];
        foreach ($this->values as $value) {
            $class = is_string($value) ? $policy->named($value) : null;
            if ($class !== null) {
                $classes[] = $class;
            }
        }

        return $classes;
    }

    /**
     * The requested classes among the given ones, in the client's order: those a login can still prove
     * when the given ones are what the provider proves (§5.5.1.1).
     *
     * @param list<AuthenticationContextClass> $classes
     *
     * @return list<AuthenticationContextClass>
     */
    public function among(array $classes): array
    {
        $among = [];
        foreach ($this->values as $value) {
            foreach ($classes as $class) {
                if ($class->value === $value) {
                    $among[] = $class;
                }
            }
        }

        return $among;
    }

    /**
     * In the client's order of preference; null when the session satisfies none.
     */
    public function firstSatisfiedBy(AuthenticationSession $session): ?AuthenticationContextClass
    {
        foreach ($this->classesOf($session->tenant->authenticationContextPolicy) as $class) {
            if ($session->satisfies($class)) {
                return $class;
            }
        }

        return null;
    }
}
