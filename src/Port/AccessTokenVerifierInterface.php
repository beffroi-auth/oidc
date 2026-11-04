<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Exception\InvalidTokenException;
use SensitiveParameter;

interface AccessTokenVerifierInterface extends AccessTokenShapeInterface
{
    /**
     * Reads the shape alone, never a store or a signature: verify() may still refuse a value this recognises.
     */
    public function recognises(#[SensitiveParameter] string $accessToken): bool;

    public function expiresOnItsOwn(): bool;

    /**
     * @throws InvalidTokenException
     */
    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken;
}
