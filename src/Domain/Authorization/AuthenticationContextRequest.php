<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_any;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationSession;
use function in_array;
use function is_string;

/**
 * What a request says about the "acr" of the ID token (OIDC Core §3.1.2.1, §5.5.1.1): the "acr" claim
 * request of "claims.id_token" first, "acr_values" as the voluntary form otherwise. A value that is not
 * a string names no class and matches none.
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
     * Whether a requested class is one the provider can assert at all (§5.5.1.1).
     *
     * @param non-empty-list<string> $supported
     */
    public function canBeMetWith(array $supported): bool
    {
        return array_any($this->values, static fn (string|int|float|bool $value): bool => in_array($value, $supported, true));
    }

    /**
     * In the client's order of preference; null when the session satisfies none.
     */
    public function firstSatisfiedBy(AuthenticationSession $session): ?AuthenticationContextClass
    {
        foreach ($this->values as $value) {
            if (! is_string($value) || ! AuthenticationContextClass::isWellFormed($value)) {
                continue;
            }
            $class = new AuthenticationContextClass($value);
            if ($session->satisfies($class)) {
                return $class;
            }
        }

        return null;
    }
}
