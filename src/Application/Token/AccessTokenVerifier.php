<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AccessTokenVerifierInterface;
use SensitiveParameter;

/**
 * Reads back an access token of this provider, whatever shape it was written in (architecture §4.6): it
 * hands the token to the wired verifier that recognises its shape, and to no other.
 *
 * It knows no shape of its own. A shape the provider gains is a verifier beside the issuer that writes
 * it and a line in the wiring, and nothing here changes; what the provider knows beyond the token,
 * whether the session has ended, whether the grant is still alive and whether the user is still served,
 * is asked once and for every shape in AccessTokenInspector.
 */
final readonly class AccessTokenVerifier
{
    /**
     * @param iterable<AccessTokenVerifierInterface> $verifiers one per shape the provider writes
     */
    public function __construct(
        private iterable $verifiers,
    ) {
    }

    /**
     * @throws InvalidTokenException when no wired shape recognises the token, or when the one that does
     *                               refuses it
     */
    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        return $this->recognising($accessToken)->verify($tenant, $accessToken, $now);
    }

    /**
     * Whether the token carries its own claims and therefore cannot be taken back (RFC 7009 §2.2.1). The
     * shape that recognises it answers; a shape nothing recognises is not one of ours and expires
     * nowhere, which the caller reads as nothing to revoke.
     */
    public function expiresOnItsOwn(#[SensitiveParameter] string $accessToken): bool
    {
        return self::recognisedBy($this->verifiers, $accessToken)?->expiresOnItsOwn() ?? false;
    }

    /**
     * @throws InvalidTokenException
     */
    private function recognising(#[SensitiveParameter] string $accessToken): AccessTokenVerifierInterface
    {
        return self::recognisedBy($this->verifiers, $accessToken) ?? throw InvalidTokenException::notIssuedHere();
    }

    /**
     * The wired shape this value has, null when it has none: asked once, by both the reading and the
     * question the revocation endpoint asks before it looks anything up.
     *
     * @param iterable<AccessTokenVerifierInterface> $verifiers
     */
    private static function recognisedBy(iterable $verifiers, #[SensitiveParameter] string $accessToken): ?AccessTokenVerifierInterface
    {
        foreach ($verifiers as $verifier) {
            if ($verifier->recognises($accessToken)) {
                return $verifier;
            }
        }

        return null;
    }
}
