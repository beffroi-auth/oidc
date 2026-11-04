<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use function array_any;
use function array_key_exists;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use function in_array;
use function sprintf;

/**
 * The wired claims providers answering as one, walked on each call so that each is built only when needed.
 */
final readonly class ServedClaims implements ClaimsProviderInterface
{
    /**
     * @param iterable<ClaimsProviderInterface> $providers
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

    public function claimsOf(Scopes $scopes): array
    {
        $claims = new ClaimNames();
        foreach ($this->providers as $provider) {
            $claims = $claims->with(new ClaimNames($provider->claimsOf($scopes)));
        }

        return $claims->all;
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
