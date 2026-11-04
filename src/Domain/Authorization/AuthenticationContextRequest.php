<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationContextPolicy;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use function is_string;

/**
 * OIDC Core §3.1.2.1, §5.5.1.1
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

    public function namesNoClass(): bool
    {
        return $this->values === [];
    }

    /**
     * OIDC Core §5.5.1.1
     */
    public function demandsAClass(): bool
    {
        return $this->essential && ! $this->namesNoClass();
    }

    /**
     * @return list<AuthenticationContextClass> in the client's order of preference
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
     * @param list<AuthenticationContextClass> $classes
     *
     * @return list<AuthenticationContextClass> in the client's order of preference
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
