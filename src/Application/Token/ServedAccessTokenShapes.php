<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_values;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\AuthorizationInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use function implode;
use function sprintf;

/**
 * The shapes the wiring gave the provider, in the order they are wired. The one source of truth over
 * them (issue #98): a registration reads this list to know what a client may name, the retirement of a
 * signing key reads it to know what is still being written, and the token endpoint mints through it.
 *
 * It demands no shape in particular, so a deployment that wires one boots, and it refuses two issuers
 * that write the same shape, which is a wiring where the token a client receives depends on an order
 * nobody wrote down.
 *
 * The list is read when a question is asked of it and never at construction, because a client
 * registration asks it what a client may name while the clients are themselves being built.
 */
final readonly class ServedAccessTokenShapes implements AccessTokenIssuerInterface, ServedAccessTokenShapesInterface
{
    /**
     * @param iterable<AccessTokenShapeIssuerInterface> $issuers at least one, each naming the shape it writes
     */
    public function __construct(
        private iterable $issuers,
    ) {
    }

    public function servedAccessTokenShapes(): array
    {
        return array_values($this->wired());
    }

    /**
     * Architecture §4.6: the shape the client registered says who writes the token, and that issuer
     * alone mints it.
     *
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken
    {
        $shape = $authorization->client->registration->accessTokenShape->name();
        $wired = $this->wired();

        return ($wired[$shape] ?? throw new InvalidArgumentException(sprintf(
            'No issuer writes access tokens in the "%s" shape; the wired shapes are %s.',
            $shape,
            implode(', ', ShapeNames::of(array_values($wired))),
        )))->issue($authorization, $now);
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<non-empty-string, AccessTokenShapeIssuerInterface> by the name each issuer gives its shape
     */
    private function wired(): array
    {
        $wired = [];
        foreach ($this->issuers as $issuer) {
            $name = $issuer->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('Two issuers write access tokens in the "%s" shape.', $name));
            }
            $wired[$name] = $issuer;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('A provider writes its access tokens in at least one shape.');
        }

        return $wired;
    }
}
