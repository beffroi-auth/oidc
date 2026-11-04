<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_values;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\AccessTokenIssuerInterface;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Beffroi\Oidc\Port\ServedAccessTokenShapesInterface;
use function implode;
use function sprintf;

/**
 * The issuers are read on first use, never at construction: a client registration reads them while the clients
 * are being built.
 */
final readonly class ServedAccessTokenShapes implements AccessTokenIssuerInterface, ServedAccessTokenShapesInterface
{
    /**
     * @param iterable<AccessTokenShapeIssuerInterface> $issuers at least one
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
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function address(Client $client): AddressedAccessToken
    {
        return $this->issuerOf($client)->address($client);
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
    {
        return $this->issuerOf($authorization->client)->addressFor($authorization);
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        return $this->issuerOf($authorization->client)->issue($authorization, $addressed, $now);
    }

    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    private function issuerOf(Client $client): AccessTokenShapeIssuerInterface
    {
        $shape = $client->registration->accessTokenShape->name();
        $wired = $this->wired();

        return $wired[$shape] ?? throw new InvalidArgumentException(sprintf(
            'No issuer writes access tokens in the "%s" shape; the wired shapes are %s.',
            $shape,
            implode(', ', ShapeNames::of(array_values($wired))),
        ));
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-array<non-empty-string, AccessTokenShapeIssuerInterface> by shape name
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
