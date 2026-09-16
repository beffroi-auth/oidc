<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_any;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationSession;
use function in_array;
use function is_string;

/**
 * What a request says about the "acr" of the ID token (OIDC Core §3.1.2.1, §5.5.1.1): the classes it
 * would accept, in its order of preference, and whether meeting one of them is a condition of the
 * authentication. An individual claim request for "acr" in "claims.id_token" is read first, its "values"
 * or its "value" being the classes and its "essential" the condition; without one, "acr_values" is the
 * voluntary form of the same request. Core leaves both at once unspecified: the individual request is
 * the more specific, it wins.
 *
 * The values are kept as the client sent them (see ClaimRequest): a JSON number or boolean names no
 * class, and matches none, which is the ordinary outcome of asking for a class the provider does not
 * have, not a malformed request.
 */
final readonly class AuthenticationContextRequest
{
    /**
     * @param list<string|int|float|bool> $values the class references requested, in order of preference
     * @param bool $essential whether the authentication fails when none can be met (§5.5.1.1)
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
     * Nothing was asked, or an essential claim without a value: any class of the session will do.
     */
    public function namesNoClass(): bool
    {
        return $this->values === [];
    }

    /**
     * Whether a requested class is one the provider can assert at all, whatever the session. An
     * essential request that fails this is a failed authentication before any login (§5.5.1.1).
     *
     * @param non-empty-list<string> $supported what AuthenticationContextClass::supported() lists
     */
    public function canBeMetWith(array $supported): bool
    {
        return array_any($this->values, static fn (string|int|float|bool $value): bool => in_array($value, $supported, true));
    }

    /**
     * The first requested class the session satisfies, the client's order of preference being the
     * provider's; null when the session satisfies none, which the caller answers with the current class
     * of the session when the request is voluntary (§5.5.1.1).
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
