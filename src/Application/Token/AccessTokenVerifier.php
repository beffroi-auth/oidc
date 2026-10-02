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

/**
 * Reads back an access token of this provider, whatever shape it was written in (architecture §4.6): it
 * hands the token to the wired verifier that recognises its shape, and to no other.
 *
 * It knows no shape of its own. A shape the provider gains is a verifier beside the issuer that writes
 * it and a line in the wiring, and nothing here changes; what the provider knows beyond the token,
 * whether the session has ended, whether the grant is still alive and whether the user is still served,
 * is asked once and for every shape in AccessTokenInspector.
 *
 * It is also where the two sides of a shape are made to meet: a token this provider writes and cannot
 * read back is a token nobody can spend, so a wiring where a shape has no verifier, or where a verifier
 * reads a shape nothing writes, is refused here rather than discovered at a resource server.
 */
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
     *
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
     * The wired shape this value has, null when it has none: asked once, by both the reading and the
     * question the revocation endpoint asks before it looks anything up.
     *
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
     * @return non-empty-array<non-empty-string, AccessTokenVerifierInterface> by the name each one gives its shape
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
