<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use SensitiveParameter;

/**
 * How a resource of this provider reads back an access token of one shape (architecture §4.6), the
 * counterpart of the issuer that wrote it (AccessTokenIssuerInterface). A shape the provider gains is a
 * class on each side and a line in the wiring, and nothing anywhere reads a token to guess its kind.
 *
 * Each verifier recognises what it writes, so that nothing outside has to know what a token of that
 * shape looks like: a self-contained token and an opaque reference are told apart by the two classes
 * that produce them and by no test written a third time.
 */
interface AccessTokenVerifierInterface
{
    /**
     * Whether this value has the shape this verifier writes back. It is the shape alone that is read
     * here, never a store and never a signature: a value nothing recognises was not issued here, and a
     * value this recognises may still be refused by verify().
     */
    public function recognises(#[SensitiveParameter] string $accessToken): bool;

    /**
     * Whether a token of this shape carries its own claims and therefore expires on its own, which is
     * what makes it one no endpoint can take back (RFC 7009 §2.2.1).
     */
    public function expiresOnItsOwn(): bool;

    /**
     * @throws InvalidTokenException when the token was not issued by this tenant, or has expired
     */
    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken;
}
