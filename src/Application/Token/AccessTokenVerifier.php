<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_any;
use function array_keys;
use function array_values;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Port\AccessTokenVerifierInterface;
use Beffroi\Oidc\Port\ServedAccessTokenShapesInterface;
use function implode;
use SensitiveParameter;
use function sprintf;

final readonly class AccessTokenVerifier
{
    /**
     * @param iterable<AccessTokenVerifierInterface> $verifiers one per shape the provider writes
     */
    public function __construct(
        private iterable $verifiers,
        private ServedAccessTokenShapesInterface $shapes,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     * @throws InvalidTokenException
     */
    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        return $this->recognising($accessToken)->verify($tenant, $accessToken, $now);
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function expiresOnItsOwn(#[SensitiveParameter] string $accessToken): bool
    {
        return $this->recognisedBy($accessToken)?->expiresOnItsOwn() ?? false;
    }

    /**
     * @throws InvalidArgumentException
     * @throws InvalidTokenException
     */
    private function recognising(#[SensitiveParameter] string $accessToken): AccessTokenVerifierInterface
    {
        return $this->recognisedBy($accessToken) ?? throw InvalidTokenException::notIssuedHere();
    }

    /**
     * @throws InvalidArgumentException
     */
    private function recognisedBy(#[SensitiveParameter] string $accessToken): ?AccessTokenVerifierInterface
    {
        foreach ($this->wired() as $verifier) {
            if ($verifier->recognises($accessToken)) {
                return $verifier;
            }
        }

        return null;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<non-empty-string, AccessTokenVerifierInterface> by shape name
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->verifiers as $verifier) {
            $name = $verifier->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('Two verifiers read access tokens of the "%s" shape back.', $name));
            }
            $wired[$name] = $verifier;
        }
        $written = $this->shapes->servedAccessTokenShapes();
        foreach ($written as $shape) {
            if (! isset($wired[$shape->name()])) {
                throw new InvalidArgumentException(sprintf(
                    'The provider writes access tokens in the "%s" shape and nothing reads them back.',
                    $shape->name(),
                ));
            }
        }
        foreach (array_keys($wired) as $name) {
            if (! array_any($written, static fn (AccessTokenShapeInterface $shape): bool => $shape->name() === $name)) {
                throw new InvalidArgumentException(sprintf(
                    'A verifier reads access tokens of the "%s" shape back and nothing writes them; the wired shapes are %s.',
                    $name,
                    implode(', ', ShapeNames::of(array_values($written))),
                ));
            }
        }

        /** @var non-empty-array<non-empty-string, AccessTokenVerifierInterface> $wired */
        return $wired;
    }
}
