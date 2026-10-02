<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use function array_any;
use function array_key_exists;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use function in_array;
use function sprintf;

/**
 * The claims providers the wiring gave this provider, answering as one (OIDC Core §5.1). The standard
 * claims of §5.1 are one of them, closed by the specification; the claims of a deployment, and the scope
 * that stands for them, are a class beside it and a line in the wiring, never a map of scopes edited.
 *
 * What each one serves it says itself, and what the document announces is read from them (§4.8): a scope
 * of a deployment is announced because a class serves it, exactly as a grant is announced because a class
 * is wired to serve it (issue #98).
 *
 * Two providers that both put a value on the same claim are refused where the values meet: which of the
 * two a client would receive is not something a deployment should have to guess, as it is not for a
 * member of the discovery document. Two that serve the same scope are not refused: a scope is a name for
 * a set of claims, and what each provider puts under that name is its own.
 *
 * The providers are walked when a question is asked and never at construction, so that one is built when
 * a claim of it is due.
 */
final readonly class ServedClaims implements ClaimsProviderInterface
{
    /**
     * @param iterable<ClaimsProviderInterface> $providers in the order they are wired; none is a
     *                                                     deployment that serves "sub" and nothing else
     */
    public function __construct(
        private iterable $providers,
    ) {
    }

    /**
     * @throws InvalidArgumentException when two providers put a value on the same claim
     */
    public function claims(User $user, ?Scopes $scopes, array $requested): array
    {
        $claims = [];
        foreach ($this->providers as $provider) {
            foreach ($provider->claims($user, $scopes, $requested) as $claim => $value) {
                if (array_key_exists($claim, $claims)) {
                    throw new InvalidArgumentException(sprintf('Two claims providers of this provider both serve "%s".', $claim));
                }
                $claims[$claim] = $value;
            }
        }

        return $claims;
    }

    public function supportedScopes(): array
    {
        $scopes = [];
        foreach ($this->providers as $provider) {
            foreach ($provider->supportedScopes() as $scope) {
                if (! array_any($scopes, static fn (Scope $kept): bool => $kept->equals($scope))) {
                    $scopes[] = $scope;
                }
            }
        }

        return $scopes;
    }

    public function supportedClaims(): array
    {
        $claims = [];
        foreach ($this->providers as $provider) {
            foreach ($provider->supportedClaims() as $claim) {
                if (! in_array($claim, $claims, true)) {
                    $claims[] = $claim;
                }
            }
        }

        return $claims;
    }
}
